// navigation.js - 处理顶部导航栏的活动状态和交互功能
document.addEventListener('DOMContentLoaded', function() {
    // 获取当前页面路径
    const currentPath = window.location.pathname;
    
    // 获取所有导航项
    const navItems = document.querySelectorAll('.nav-item');
    
    // 根据当前路径设置活动状态
    navItems.forEach(item => {
        const href = item.getAttribute('href');
        
        // 检查当前路径是否匹配导航项
        if (
            (href.includes('/file/') && currentPath.includes('/file/')) ||
            (href.includes('/company/') && currentPath.includes('/company/')) ||
            (href.includes('/agent/') && currentPath.includes('/agent/')) ||
            (href.includes('/alert/') && currentPath.includes('/alert/')) ||
            (href.includes('/manage') && currentPath === '/manage/') ||
            (href.includes('/index') && currentPath === '/')
        ) {
            item.classList.add('active');
        }
    });
    
    // 为导航项添加点击事件，展开侧边栏
    navItems.forEach(item => {
        item.addEventListener('click', function(e) {
            // 移除所有导航项的活动状态
            navItems.forEach(nav => nav.classList.remove('active'));
            
            // 为当前点击的导航项添加活动状态
            this.classList.add('active');
        });
    });
});