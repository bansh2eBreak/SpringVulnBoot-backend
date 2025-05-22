-- 设置数据库字符集
ALTER DATABASE SpringVulnBoot CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;

-- 创建管理员表
create table if not exists Admin
(
    id          int auto_increment
        primary key,
    name        varchar(50)                                                                                                         not null,
    username    varchar(50)                                                                                                         not null,
    password    varchar(50)                                                                                                         not null,
    token       varchar(255)                                                                                                        null,
    avatar      varchar(255) default 'https://img1.baidu.com/it/u=3200425930,2413475553&fm=253&fmt=auto&app=120&f=JPEG?w=800&h=800' null,
    create_time datetime                                                                                                            null,
    constraint username
        unique (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 插入测试数据到Admin表
INSERT INTO Admin (name, username, password, token) VALUES ('系统管理员','admin', '123456', CONCAT('token_', ROUND(UNIX_TIMESTAMP(CURTIME(4)) * 1000)));
INSERT INTO Admin (name, username, password, token) VALUES ('审计员','zhangsan', '123456', CONCAT('token_', ROUND(UNIX_TIMESTAMP(CURTIME(4)) * 1000)));

-- 创建留言表
create table if not exists MessageBoard
(
    id      int auto_increment
        primary key,
    message varchar(200) null
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 创建用户表
create table if not exists User
(
    id       int auto_increment
        primary key,
    username varchar(50) null,
    name     varchar(50) null,
    password varchar(50) null
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 创建MFA密钥表
create table if not exists mfa_secret
(
    id          int auto_increment
        primary key,
    userId      int          not null comment '用户ID',
    secret      varchar(100) not null comment 'MFA加密串',
    create_time datetime     null comment '创建时间',
    update_time datetime     null comment '更新时间',
    constraint mfa_secret_Admin_id_fk
        foreign key (userId) references Admin (id)
)
    comment 'MFA密钥表' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

create index userId
    on mfa_secret (userId);

-- 创建短信验证码记录表
create table if not exists sms_code
(
    id          bigint auto_increment
        primary key,
    phone       varchar(20)   not null comment '手机号',
    code        varchar(6)    not null comment '验证码',
    create_time datetime      not null comment '创建时间',
    expire_time datetime      not null comment '过期时间',
    used        int default 0 null comment '是否已使用：0未使用，1已使用',
    retry_count int default 0 null comment '验证重试次数'
)
    comment '短信验证码记录表' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 创建用户登录日志表
create table if not exists user_login_log
(
    id        int auto_increment
        primary key,
    ip        varchar(50)  not null,
    username  varchar(255) not null,
    loginTime datetime     not null
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 插入测试数据到MessageBoard表
INSERT INTO MessageBoard (id, message) VALUES (1, '这个靶场真棒！');
INSERT INTO MessageBoard (id, message) VALUES (2, '怎么没有命令执行漏洞系列？');
INSERT INTO MessageBoard (id, message) VALUES (3, '催更！！！');
INSERT INTO MessageBoard (id, message) VALUES (4, '<img src=x onmouseover=alert(/xss/)>');

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
