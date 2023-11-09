from django.shortcuts import render, HttpResponse


def loginView(request):
    if request.method == 'GET':
        return HttpResponse('verify your username or password')
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        if username and password:
            return HttpResponse("your are login successfully")


def registerView(request):
    if request.method == 'Get':
        # form = RegisterForm()
        return HttpResponse("form of registration")

    if request.method == 'POST':
        form = RegisterForm()
        if form.is_valid():
            form.save()
            return HttpResponse("your are registered")
        return HttpResponse("form is not valid")