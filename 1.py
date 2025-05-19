import matplotlib.pyplot as plt
import seaborn as sns

# Define the categories and their corresponding sizes
categories = ["鉴权类漏洞", "注册接受类漏洞", "呼叫/激活类漏洞", "密钥与安全模式类漏洞", "特殊标识与紧急处理类漏洞"]
sizes = [20, 30, 10, 25, 15]  # Example sizes, you can adjust these based on your data

# Set up the plot
fig, ax = plt.subplots(figsize=(7, 7))

# Create a pie chart
ax.pie(sizes, labels=categories, autopct='%1.1f%%', startangle=90, colors=sns.color_palette("Set2", len(categories)))

# Equal aspect ratio ensures that pie is drawn as a circle.
ax.axis('equal')

# Add title
plt.title("漏洞分类分布")

# Show the chart
plt.show()
