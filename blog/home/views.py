from django.shortcuts import render, redirect
from django.urls import reverse

# Create your views here.

from django.views import View
from home.models import ArticleCategory,Article
from django.http.response import HttpResponseNotFound
from django.core.paginator import Paginator,EmptyPage

class IndexView(View):
    """首页广告"""

    def get(self, request):
        """提供首页广告界面"""

        # 判断分类id

        # 获取博客分类信息
        categories = ArticleCategory.objects.all()

        cat_id = request.GET.get('cat_id', 1)

        try:
            category = ArticleCategory.objects.get(id=cat_id)
        except ArticleCategory.DoesNotExist:
            return HttpResponseNotFound('没有此分类')




        page_num = request.GET.get('page_num',1)
        page_size = request.GET.get('page_size',10)
        articles = Article.objects.filter(category=category)
        paginator = Paginator(articles, per_page=page_size)

        try:
            page_articles = paginator.page(page_num)
        except EmptyPage:
            # 如果没有分页数据，默认给用户404
            return HttpResponseNotFound('empty page')

        total_page = paginator.num_pages


        context = {
            'categories': categories,
            'category': category,
            'articles': page_articles,
            'page_size': page_size,
            'total_page': total_page,
            'page_num': page_num
        }

        return render(request, 'index.html', context=context)



