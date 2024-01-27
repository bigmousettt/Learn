%% (1)F = fillmissing(A,method)使用method指定的方法填充缺失条目
% 创建包含 NaN 值的向量，并使用*前一个非缺失值*替换每个 NaN。
A = [1 3 NaN 4 NaN NaN 5];
F = fillmissing(A,'previous')

%% 使用移动中位数填充缺失的数值数据。
% 创建样本点向量x和包含确实值得数据向量A
x = linspace(0,10,200); 
A = sin(x) + 0.5*(rand(size(x))-0.5); 
A([1:10 randi([1 length(x)],1,50)]) = NaN; 
% 使用窗长度为 10 的移动中位数替换 A 中的 NaN 值，并绘制原始数据和填充的数据。
F = fillmissing(A,'movmedian',10);  
plot(x,F,'.-') 
hold on
plot(x,A,'.-')
legend('Original Data','Filled Data')

%% 使用插值来替换非均匀采样的数据中的 NaN 值。
% 定义非均匀采样点向量，并计算这些点上的正弦函数。
x = [-4*pi:0.1:0, 0.1:0.2:4*pi];
A = sin(x);
% 将 NaN 值插入 A 中。
A(A < 0.75 & A > 0.5) = NaN;
% 使用线性插值填充缺失数据，并返回填充的向量 F 和逻辑向量 TF。TF 项中的值 1 (true) 对应于 F 中的填充值。
[F,TF] = fillmissing(A,'linear','SamplePoints',x);
% 绘制原始数据和填充的数据。
scatter(x,A)
hold on
scatter(x(TF),F(TF))
legend('Original Data','Filled Data')

%% F = fillmissing(A,'constant',v) 使用常量值 v 填充缺失的数组或表条目。
%% 使用不同数据类型填充表变量的缺失值。
% 创建表，其变量包括 categorical、double 和 char 数据类型。
A = table(categorical({'Sunny'; 'Cloudy'; ''}),[66; NaN; 54],{''; 'N'; 'Y'},[37; 39; NaN],...
    'VariableNames',{'Description' 'Temperature' 'Rain' 'Humidity'})
% 用上一个条目的值替换所有缺失的条目。由于 Rain 变量中不存在前一个元素，缺失的字符向量将不会被替换。
F = fillmissing(A,'previous')
% 将 A 中 Temperature 和 Humidity 变量的 NaN 值替换为 0。
F = fillmissing(A,'constant',0,'DataVariables',{'Temperature','Humidity'})
% 使用 isnumeric 函数识别要对其执行运算的数字变量。
F = fillmissing(A,'constant',0,'DataVariables',@isnumeric)
%用包含在元胞数组中的指定常量来填充 A 中每个表变量的缺失值。
F = fillmissing(A,'constant',{categorical({'None'}),1000,'Unknown',1000})
%% test_categorical:
B = table(categorical({'S'; 'C'; 'R'}),[66; NaN; NaN],{''; 'N'; 'Y'},[37; 39; NaN],...
    'VariableNames',{'Description' 'Temperature' 'Rain' 'Humidity'})
F_B = fillmissing(B,'constant',{categorical({'None'}),600,'Y',1000})

%% 