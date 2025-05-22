import requests
import re

def fetch_all_links(url):
    # 不安全：没有设置超时和响应大小限制
    response = requests.get(url)  # 这里存在资源耗尽漏洞
    
    # 使用正则表达式提取所有链接
    links = re.findall(r'href=[\'"]?([^\'" >]+)', response.text)
    
    # 处理提取的链接
    for link in links:
        print(f"找到链接: {link}")
        
    return links

def crawl_website(start_url):
    print(f"开始抓取网站: {start_url}")
    
    # 获取所有链接
    links = fetch_all_links(start_url)
    
    # 递归爬取每个链接
    for link in links[:5]:  # 限制只爬取前5个链接，防止无限循环
        if link.startswith("http"):
            try:
                crawl_website(link)
            except Exception as e:
                print(f"爬取 {link} 时出错: {str(e)}")

if __name__ == "__main__":
    target_url = "http://example.com"
    crawl_website(target_url) 