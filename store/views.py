from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import render, get_object_or_404, redirect
from .models import Category, Product, Cart, CartItem, Order, OrderItem
import stripe
from django.conf import settings
from django.contrib.auth.models import Group, User
from .forms import SignUpForm
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages, auth

def home(request, category_slug=None):
    category_page = None
    products = None
    if category_slug!=None:
        category_page = get_object_or_404(Category, slug=category_slug)
        products = Product.objects.filter(category=category_page, available=True)
    else: 
        products = Product.objects.all().filter(available=True)
    return render(request, 'home.html', {'category': category_page, 'products': products})

def productPage(request, category_slug, product_slug):
    try:
        product = Product.objects.get(category__slug=category_slug, slug=product_slug)
    except Exception as e:
        raise e
    return render(request, 'product.html', {'product': product})

def _cart_id(request):
    cart = request.session.session_key
    if not cart:
        cart = request.session.create()
    return cart

def add_cart(request, product_id):
    product = Product.objects.get(id=product_id)
    try:
        cart = Cart.objects.get(cart_id=_cart_id(request))
    except Cart.DoesNotExist:
        cart = Cart.objects.create(
            cart_id = _cart_id(request)
        )
        cart.save()
    try:
        cart_item = CartItem.objects.get(product=product, cart=cart)
        if cart_item.quantity < cart_item.product.stock:
            cart_item.quantity += 1
        cart_item.save()
    except CartItem.DoesNotExist:
        cart_item = CartItem.objects.create(
                product = product,
                quantity = 1,
                cart = cart
        )
        cart_item.save()
    return redirect('cart_detail')

def cart_detail(request, total=0, counter=0, cart_items = None):
    try:
        cart = Cart.objects.get(cart_id=_cart_id(request))
        cart_items = CartItem.objects.filter(cart=cart, active=True)
        for cart_item in cart_items:
            total += (cart_item.product.price * cart_item.quantity)
            counter += cart_item.quantity
    except ObjectDoesNotExist:
        pass

    stripe.api_key = settings.STRIPE_SECRET_KEY
    stripe_total = int(total * 100)
    description = 'Z-Store - New Order'
    data_key = settings.STRIPE_PUBLISHABLE_KEY
    if request.method == 'POST':
        try:
            token = request.POST['stripeToken']
            email = request.POST['stripeEmail']
            billingName = request.POST['stripeBillingName']
            billingAddress1 = request.POST['stripeBillingAddressLine1']
            billingCity = request.POST['stripeBillingAddressCity']
            billingPostcode = request.POST['stripeBillingAddressZip']
            billingCountry = request.POST['stripeBillingAddressCity']
            shippingName = request.POST['stripeShippingName']
            shippingAddress1 = request.POST['stripeShippingAddressLine1']
            shippingCity = request.POST['stripeShippingAddressCity']
            shippingPostcode = request.POST['stripeShippingAddressZip']
            shippingCountry = request.POST['stripeShippingAddressCountryCode']

            customer = stripe.Customer.create(
                        email=email,
                        source = token
            )
            charge = stripe.Charge.create(
                        amount=stripe_total,
                        currency='cad',
                        description=description,
                        customer=customer.id
            )
            # Creating the order
            try:
                order_details = Order.objects.create(
                    token=token,
                    total=total,
                    emailAddress=email,
                    billingName=billingName,
                    billingAddress1=billingAddress1,
                    billingCity=billingCity,
                    billingPostcode=billingPostcode,
                    billingCountry=billingCountry,
                    shippingName=shippingName,
                )
                order_details.save()
                for order_item in cart_items:
                    or_item = OrderItem.objects.create(
                            product = order_item.product.name,
                            quantity = order_item.quantity,
                            price = order_item.product.price,
                            order = order_details
                    )
                    or_item.save()

                    #reduce stock
                    products = Product.objects.get(id=order_item.product.id)
                    products.stock = int(order_item.product.stock - order_item.quantity)
                    products.save()
                    order_item.delete()

                    print('the order has been created')
                return redirect('thanks_page', order_details.id)
            except ObjectDoesNotExist:
                pass

        except stripe.error.CardError as e:
            return False,e

    return render(request, 'cart.html', dict(cart_items = cart_items, total = total, counter = counter, data_key = data_key, stripe_total = stripe_total, description = description))

def signup(request):
    if request.method == 'POST':
        # Get form values
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        password2 = request.POST['password2']

        # Check if passwords match
        if password == password2:
           # Check if username is already in database
            if User.objects.filter(username=username).exists():
                messages.error(request, 'That username is taken')
                return redirect('signup')
            else: 
                # Check if email address is already in database
                if User.objects.filter(email=email).exists():
                    messages.error(request, 'That email address is taken')
                    return redirect('signup')
                else: 
                    # can register this user!
                    user = User.objects.create_user(username=username, password=password, 
                    email=email, first_name=first_name, last_name=last_name)
                    # Login after register
                    # auth.login(request, user)
                    # messages.success(request, 'You are now logged in!')
                    # return redirect('index')

                    user.save()
                    messages.success(request, 'You are now registered. Please login')
                    return redirect('signin')
        else: 
            messages.error(request, 'Passwords do not match')
            return redirect('signup')
    else: 
        return render(request, 'signup.html')

def signin(request):
    if request.method == 'POST':
        # get 'username' and 'password' input value from form
        username = request.POST['username']
        password = request.POST['password']
        # 1 authenticate user using authenticate() method.
        user = auth.authenticate(username=username, password=password)
        # check if user exists in database
        if user is not None:
            # 2 log-in a user. so authenticate first to check if user credential is valid. 
            # if so, login a user -- IMPORTANT ---
            auth.login(request, user)
            return redirect('home')
        else: 
            messages.error(request, 'Invalid credentials')
            return redirect('signin')
    else:
        return render(request, 'signin.html')

def signout(request):
    # logout is a function that is registered as url
    if request.method == 'POST':
        # just call auth.logout function here.... pass in data from request.
        auth.logout(request)
        messages.success(request, 'You are now logged out')
        return redirect('signin')
    else:
        return redirect('home')


def cart_remove(request, product_id):
    cart = Cart.objects.get(cart_id=_cart_id(request))
    product = get_object_or_404(Product, id=product_id)
    cart_item = CartItem.objects.get(product=product, cart=cart)
    if cart_item.quantity > 1:
        cart_item.quantity -= 1
        cart_item.save()
    else:
        cart_item.delete()
    return redirect('cart_detail')


def cart_remove_product(request, product_id):
    cart = Cart.objects.get(cart_id=_cart_id(request))
    product = get_object_or_404(Product, id=product_id)
    cart_item = CartItem.objects.get(product=product, cart=cart) 
    cart_item.delete()
    return redirect('cart_detail')   

def thanks_page(request, order_id):
    if order_id:
        customer_order = get_object_or_404(Order, id=order_id)
    return render(request, 'thankyou.html', {'customer_order': customer_order})

@login_required(redirect_field_name='next', login_url='signin')
def orderHistory(request):
    if request.user.is_authenticated:
        email = str(request.user.email)
        order_details = Order.objects.filter(emailAddress=email)
    return render(request, 'order_list.html', {'order_details': order_details})

@login_required(redirect_field_name='next', login_url='signin')
def viewOrder(request, order_id):
    if request.user.is_authenticated:
        email = str(request.user.email)
        order = Order.objects.get(id=order_id, emailAddress=email)
        order_items = OrderItem.objects.filter(order=order)
    return render(request, 'order_detail.html', {'order': order, 'order_items': order_items})

def search(request):
    products = Product.objects.filter(name__contains=request.GET['title'])
    return render(request, 'home.html', {'products': products})