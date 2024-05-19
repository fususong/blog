from django.shortcuts import render

# Create your views here.
#z注册试图
from django.views import View

class RegisterView(View):

    def get(self, request):

        return render(request, 'register.html')