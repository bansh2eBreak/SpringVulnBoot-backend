-- 创建用户表
CREATE TABLE User (
    id INT PRIMARY KEY auto_increment,
    username VARCHAR(50),
    name VARCHAR(50),
    password VARCHAR(50)
);

-- 创建留言表
CREATE TABLE MessageBoard(
    id INT PRIMARY KEY auto_increment,
    message VARCHAR(200)
);

-- 后台管理员表
CREATE TABLE IF NOT EXISTS Admin (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(50) NOT NULL,
    token VARCHAR(255),
    avator VARCHAR(255) DEFAULT 'https://img1.baidu.com/it/u=3200425930,2413475553&fm=253&fmt=auto&app=120&f=JPEG?w=800&h=800'
);

-- 插入测试数据到MessageBoard表
INSERT INTO MessageBoard (id, message) VALUES (1, '这个靶场真棒！');
INSERT INTO MessageBoard (id, message) VALUES (2, '怎么没有命令执行漏洞系列？');
INSERT INTO MessageBoard (id, message) VALUES (3, '催更！！！');

-- 插入测试数据到Admin表
INSERT INTO Admin (username, password, token) VALUES ('admin', '123456', CONCAT('token_', ROUND(UNIX_TIMESTAMP(CURTIME(4)) * 1000)));

-- 插入测试数据到User表
INSERT INTO User (id, username, name, password) VALUES (1, 'zhangsan', '张三', '123');
INSERT INTO User (id, username, name, password) VALUES (2, 'lisi', '李四', '123');
INSERT INTO User (id, username, name, password) VALUES (3, 'wangwu', '王五', '123');
INSERT INTO User (id, username, name, password) VALUES (4, 'user4', 'User 4', '123');
INSERT INTO User (id, username, name, password) VALUES (5, 'user5', 'User 5', '123');
INSERT INTO User (id, username, name, password) VALUES (6, 'user6', 'User 6', '123');
INSERT INTO User (id, username, name, password) VALUES (7, 'user7', 'User 7', '123');
INSERT INTO User (id, username, name, password) VALUES (8, 'user8', 'User 8', '123');
INSERT INTO User (id, username, name, password) VALUES (9, 'user9', 'User 9', '123');
INSERT INTO User (id, username, name, password) VALUES (10, 'user10', 'User 10', '123');
INSERT INTO User (id, username, name, password) VALUES (11, 'user11', 'User 11', '123');
INSERT INTO User (id, username, name, password) VALUES (12, 'user12', 'User 12', '123');
INSERT INTO User (id, username, name, password) VALUES (13, 'user13', 'User 13', '123');
INSERT INTO User (id, username, name, password) VALUES (14, 'user14', 'User 14', '123');
INSERT INTO User (id, username, name, password) VALUES (15, 'user15', 'User 15', '123');
INSERT INTO User (id, username, name, password) VALUES (16, 'user16', 'User 16', '123');
INSERT INTO User (id, username, name, password) VALUES (17, 'user17', 'User 17', '123');
INSERT INTO User (id, username, name, password) VALUES (18, 'user18', 'User 18', '123');
INSERT INTO User (id, username, name, password) VALUES (19, 'user19', 'User 19', '123');
INSERT INTO User (id, username, name, password) VALUES (20, 'user20', 'User 20', '123');
