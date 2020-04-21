# easylogin-core

Hướng dẫn deploy easylogin service (bao gồm cả core API, demo và admin)

### Yêu cầu hệ thống

Hệ thống cần có sẵn các công cụ sau:

- Docker và docker-compose
- MySQL 5.7
- Nginx
- Git

## Cấu hình HTTP server, MySQL database

### MySQL

Để các service phía trong Docker có thể connect được vào MySQL, MySQL cần phải được cấu hình để cho phép remote connect qua địa chỉ IP.

Sửa dòng sau trong file config của MySQL (thông thường ở */etc/my.cnf* trên CentOS):

```
bind-address		= 0.0.0.0`
```

Tạo 1 user là *easylogin* và cho phép remote connect từ user này bằng cách chạy câu lệnh sau trong MySQL. Lưu ý thay *your_secret* bằng mật khẩu của bạn và nhớ lưu lại giá trị này để connect vào MySQL:

```
CREATE USER 'easylogin'@'%' IDENTIFIED BY 'your_secret';
GRANT ALL PRIVILEGES ON *easylogin.* TO 'easylogin'@'%' WITH GRANT OPTION;
```

Restart lại MySQL:

```
sudo systemctl restart mysql
```

### Nginx

Copy file *easylogin.conf* trong thư mục *nginx_conf* vào thư mục conf của Nginx (thông thường ở */etc/nginx/conf.d*).

Lưu ý thay đổi các **subdomain** và **port** của các service cho đúng nếu bạn không chạy các service ở các port mặc định:

```
upstream api_server {
    server localhost:5000 fail_timeout=0;
}

upstream admin_server {
    server localhost:8000 fail_timeout=0;
}

upstream demo_server {
    server localhost:8080 fail_timeout=0;
}

server {
    server_name api.social-login.mirabo.co.jp;
    ...
}

server {
    server_name demo.social-login.mirabo.co.jp;
    ...
}

server {
    server_name admin.social-login.mirabo.co.jp;
    ...
}
```

> Core API service **bắt buộc phải có SSL** mới có thể vận hành vì thế cần đảm bảo Nginx đã được config sử dụng SSL cho các domain tương ứng phía trên.


## Deploy EasyLogin

Clone các project, bảo đảm **2 project được đặt ngang hàng** (vì file docker-compose.yml trong project *easylogin-core* được dùng để sử dụng cho cả project *easylogin-admin*)

```
git@gitlab.com:mirabo/easylogin-core.git
git@gitlab.com:mirabo/easylogin-admin.git
```

Di chuyển vào trong thư mục chứa project *easylogin-core*. Start các service bằng lệnh sau:

```
docker-compose --env-file /dev/null up -d
```

Gõ lệnh `docker ps`, nếu kết quả có dạng như sau là thành công:

```
CONTAINER ID        IMAGE               COMMAND                 CREATED             STATUS              PORTS                    NAMES
13fd4f65f5ac        easyadmin           "sh prod.sh"            3 hours ago         Up 3 hours          0.0.0.0:8000->7000/tcp   easyadmin
13de1442c4e1        easydemo            "python demo.py 7000"   3 hours ago         Up 3 hours          0.0.0.0:8080->7000/tcp   easydemo
3e1284cbc96f        easycore            "sh gunicorn.sh"        3 hours ago         Up 3 hours          0.0.0.0:5000->7000/tcp   easycore
```
