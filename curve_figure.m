%% 在同一窗口绘制多条曲线的图像
% 假设你有两组数据  
x = 0:0.1:10; % x轴的数据点  
y1 = sin(x); % 第一条曲线的数据点  
y2 = cos(x); % 第二条曲线的数据点  
  
% 使用plot函数绘制曲线  
figure; % 创建一个新的图形窗口  
plot(x, y1, 'r-', 'LineWidth', 2); % 绘制第一条曲线，红色实线，线宽2  
hold on; % 保持当前图形，以便在同一张图上绘制更多曲线  
plot(x, y2, 'b--', 'LineWidth', 2); % 绘制第二条曲线，蓝色虚线，线宽2  
hold off; % 释放当前图形，之后绘制将创建新图或覆盖旧图  
  
% 添加图例、标题和轴标签  
legend('sin(x)', 'cos(x)'); % 添加图例  
title('Comparison of sin(x) and cos(x)'); % 添加标题  
xlabel('x'); % 添加x轴标签  
ylabel('y'); % 添加y轴标签  
grid on; % 添加网格线

%% 指定线图的坐标区
%使用 tiledlayout 和 nexttile 函数显示分块图。
% Create data and 2-by-1 tiled chart layout
x = linspace(0,3);
y1 = sin(5*x);
y2 = sin(15*x);
tiledlayout(2,1) %调用 tiledlayout 函数以创建一个 2×1 分块图布局。

% Top plot
ax1 = nexttile; %调用 nexttile 函数创建一个坐标区对象，并将该对象返回为 ax1
plot(ax1,x,y1,'k-') %使用黑色实线图线
title(ax1,'Top Plot')
ylabel(ax1,'sin(5x)')

% Bottom plot
ax2 = nexttile;
plot(ax2, x, y2, 'r:'); %使用红色虚线图线
title(ax2,'Bottom Plot')
ylabel(ax2,'sin(15x)')
