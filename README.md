# easylogin-core

Hướng dẫn deploy easylogin service (bao gồm core API và demo).

## Yêu cầu hệ thống

Hệ thống cần có sẵn các công cụ sau:

- Git
- Docker và docker-compose
- MySQL 5.7
- Nginx


## Config MySQL

Để các service phía trong Docker có thể connect được vào MySQL, MySQL cần phải được cấu hình để cho phép remote connect qua địa chỉ IP.

Sửa dòng sau trong file config của MySQL (thông thường ở */etc/my.cnf* trên CentOS):

```
bind-address		= 0.0.0.0
```

Mở [MySQL CLI](https://dev.mysql.com/doc/refman/5.7/en/mysql.html). Tạo database mới với tên là *easylogin* bằng lệnh sau:

```
CREATE DATABASE easylogin CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Tạo 1 user là *easylogin* và cho phép remote connect từ user này bằng cách chạy câu lệnh sau trong MySQL. Lưu ý thay *your_secret* bằng mật khẩu của bạn và nhớ lưu lại giá trị này để connect vào MySQL:

```
CREATE USER 'easylogin'@'%' IDENTIFIED BY 'your_secret';
GRANT ALL PRIVILEGES ON easylogin.* TO 'easylogin'@'%' WITH GRANT OPTION;
```

Restart lại MySQL:

```
sudo systemctl restart mysql
```

## Deploy EasyLogin core API and demo service

Clone project từ Gitlab:

```
git clone git@gitlab.com:mirabo/easylogin-core.git
```

### Configuration

Di chuyển vào trong thư mục chứa project, tạo file *.env* để chứa các biến môi trường (nội dung tham khảo file *.env.test*). Sửa giá trị `SQLALCHEMY_DATABASE_URI` tương ứng với MySQL instance đang được sử dụng:

```
SQLALCHEMY_DATABASE_URI="mysql+pymysql://easylogin:your_secret@192.168.106.100/easylogin?charset=utf8mb4"
```

> Để biết đầy đủ các tham số có thể cấu hình, tham khảo file *config.py*


### Build and run

Build Docker images:

```
docker-compose build
```

> Docker-compose đã tự động mount thư mục code vào trong các image nên trừ khi có thay đổi về dependencies (trong file requirements) nếu không thì không cần thiết build lại Docker image mỗi khi thay đổi code.

Start các service bằng lệnh sau:

```
docker-compose up -d
```

Gõ lệnh `docker ps`, nếu kết quả có dạng như sau là thành công:

```
CONTAINER ID        IMAGE               COMMAND                 CREATED             STATUS              PORTS                    NAMES
13de1442c4e1        easydemo            "python demo.py 7000"   3 hours ago         Up 3 hours          0.0.0.0:8002->7000/tcp   easydemo
3e1284cbc96f        easycore            "sh gunicorn.sh"        3 hours ago         Up 3 hours          0.0.0.0:8001->7000/tcp   easycore
```

## Deploy with nginx

Tạo một file với tên là *easycore.conf* thư mục conf của Nginx (thông thường ở */etc/nginx/conf.d*) với nội dung như sau (lưu ý thay đổi các **subdomain** và **port** của các service cho đúng nếu bạn không chạy các service ở các port mặc định):

```
upstream api_server {
    server localhost:8001 fail_timeout=0;
}

upstream demo_server {
    server localhost:8002 fail_timeout=0;
}

server {
    server_name api.social-login.mirabo.co.jp;
    listen 443 ssl;
    listen [::]:443 ssl;

    location / {
      # checks for static file, if not found proxy to app
      try_files $uri @proxy_to_app;
    }

    location @proxy_to_app {
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_set_header Host $http_host;
      proxy_set_header X-Real-IP $remote_addr;

      # we don't want nginx trying to do something clever with
      # redirects, we set the Host: header above already.
      proxy_redirect off;
      proxy_pass http://api_server;

      proxy_set_header Connection '';
      proxy_http_version 1.1;
      chunked_transfer_encoding off;
      proxy_buffering off;
      proxy_cache off;
    }
}

server {
    server_name demo.social-login.mirabo.co.jp;
    listen 443 ssl;
    listen [::]:443 ssl;

    location / {
      # checks for static file, if not found proxy to app
      try_files $uri @proxy_to_app;
    }

    location @proxy_to_app {
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_set_header Host $http_host;
      proxy_set_header X-Real-IP $remote_addr;

      # we don't want nginx trying to do something clever with
      # redirects, we set the Host: header above already.
      proxy_redirect off;
      proxy_pass http://demo_server;

      proxy_set_header Connection '';
      proxy_http_version 1.1;
      chunked_transfer_encoding off;
      proxy_buffering off;
      proxy_cache off;
    }
}

```

> Core API service **bắt buộc phải có SSL** mới có thể vận hành vì thế cần đảm bảo Nginx đã được config sử dụng SSL cho các domain tương ứng phía trên.