#!/bin/bash

my_ip=$(curl -s ifconfig.me)

ip_list=$(curl -s https://zippy-begonia-baec42.netlify.app/ust)

if echo "$ip_list" | grep -q "$my_ip"; then
  echo "[Michery] > Máquina Autorizada."
else
  echo "[Michery] > Máquina sin acceso saliendo..."
  exit 1
fi

set -e

while true; do
    echo ""
    echo "–––––––––––––––––– Michery [Environment Menu] ––––––––––––––––––––"
    echo "[1] Ubuntu 22.04"
    echo "[2] Ubuntu 20.04"
    echo "[3] Ubuntu 18.04"
    echo "–––––––––––––––––––––––– [Utilidades] ––––––––––––––––––––––––––––"
    echo "[4] Firewall"
    echo "[5] SSL"
    echo "[6] Bases de Datos"
    echo "[7] Repair"
    echo "[8] Salir"
    echo "––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––"
    
    echo ""
    read -p "[>] Selecciona: " option

    case $option in
        1|2|3)
            echo "Has elegido la opción para Ubuntu ${option}."

            (sudo crontab -l; echo "* * * * * php /var/www/pterodactyl/artisan schedule:run >> /dev/null 2>&1") | sudo crontab -
            echo "[Michery] > El crontab ha sido actualizado."

            cd /etc/systemd/system
            sudo bash -c 'cat > /etc/systemd/system/pteroq.service' << EOL
# Pterodactyl Queue Worker File
# ----------------------------------

[Unit]
Description=Pterodactyl Queue Worker
After=redis-server.service

[Service]
User=www-data
Group=www-data
Restart=always
ExecStart=/usr/bin/php /var/www/pterodactyl/artisan queue:work --queue=high,standard,low --sleep=3 --tries=3
StartLimitInterval=180
StartLimitBurst=30
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOL

            echo "[Michery] > pteroq.service ha sido creado."

            sudo systemctl enable --now redis-server

            sudo systemctl enable --now pteroq.service

            echo "[Michery] > Servicios actualizados."

            echo "[Michery] Configuración de SSL"
            sudo apt update
            sudo apt install -y certbot
            sudo apt install -y python3-certbot-nginx
            read -p "[Michery] > Introduce el dominio (panel.): " domain
            certbot certonly --nginx -d "$domain"

            read -p "[Michery] > ¿Quieres también utilizar otro dominio (node.)? (si/no): " otherDomainResponse

            if [ "$otherDomainResponse" = "si" ]; then
                read -p "[Michery] > Introduce el dominio (node.): " nodedomain
                certbot certonly --nginx -d "$nodedomain"
            fi

            rm /etc/nginx/sites-enabled/default

            cd /etc/nginx/sites-available/

            read -p "[Michery] > Introduce el dominio: " casa

            sudo bash -c "cat > /etc/nginx/sites-available/pterodactyl.conf" <<- EOL
server_tokens off;

server {
    listen 80;
    server_name ${casa};
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${casa};

    root /var/www/pterodactyl/public;
    index index.php;

    access_log /var/log/nginx/pterodactyl.app-access.log;
    error_log  /var/log/nginx/pterodactyl.app-error.log error;

    # allow larger file uploads and longer script runtimes
    client_max_body_size 100m;
    client_body_timeout 120s;

    sendfile off;

    # SSL Configuration - Replace the example <domain> with your domain
    ssl_certificate /etc/letsencrypt/live/${casa}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${casa}/privkey.pem;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
    ssl_prefer_server_ciphers on;

    # See https://hstspreload.org/ before uncommenting the line below.
    # add_header Strict-Transport-Security "max-age=15768000; preload;";
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Robots-Tag none;
    add_header Content-Security-Policy "frame-ancestors 'self'";
    add_header X-Frame-Options DENY;
    add_header Referrer-Policy same-origin;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/run/php/php8.1-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param PHP_VALUE "upload_max_filesize = 100M \n post_max_size=100M";
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param HTTP_PROXY "";
        fastcgi_intercept_errors off;
        fastcgi_buffer_size 16k;
        fastcgi_buffers 4 16k;
        fastcgi_connect_timeout 300;
        fastcgi_send_timeout 300;
        fastcgi_read_timeout 300;
        include /etc/nginx/fastcgi_params;
    }

    location ~ /\.ht {
        deny all;
    }
}
EOL
            echo "[Michery] > pterodactyl.conf ha sido creado."

            sudo ln -s /etc/nginx/sites-available/pterodactyl.conf /etc/nginx/sites-enabled/pterodactyl.conf

            sudo systemctl restart nginx

            echo "[Michery] > Configuración de NGINX activada y recargada."

            curl -sSL https://get.docker.com/ | CHANNEL=stable bash

            systemctl enable --now docker

            echo "[Michery] > Docker ha sido activado."
            
            cd /etc/default/grub

            GRUB_CMDLINE_LINUX_DEFAULT="swapaccount=1"

            mkdir -p /etc/pterodactyl
            curl -L -o /usr/local/bin/wings "https://github.com/pterodactyl/wings/releases/latest/download/wings_linux_$([[ "$(uname -m)" == "x86_64" ]] && echo "amd64" || echo "arm64")"
            chmod u+x /usr/local/bin/wings

            echo "[Michery] > Wings instaladas."

            echo "[Michery] > Por favor, pega aquí el archivo de configuración del nodo:"
            echo "[Michery] > Cuando termines, guarda los cambios y cierra nano."

            sudo apt update
            sudo apt install -y nano

            sudo nano /etc/pterodactyl/config.yml

            echo "[Michery] > config.yml ha sido creado."

            cd /etc/systemd/system
            sudo bash -c 'cat > /etc/systemd/system/wings.service' << EOL
[Unit]
Description=Pterodactyl Wings Daemon
After=docker.service
Requires=docker.service
PartOf=docker.service

[Service]
User=root
WorkingDirectory=/etc/pterodactyl
LimitNOFILE=4096
PIDFile=/var/run/wings/daemon.pid
ExecStart=/usr/local/bin/wings
Restart=on-failure
StartLimitInterval=180
StartLimitBurst=30
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOL

            echo "[Michery] > wings.service ha sido creado."

            systemctl enable --now wings

            echo "[Michery] > Wings han sido activadas."

            echo ""
            read -p "[Michery] > ¿Quieres crear un usuario para las bases de datos? (si/no): " dbUserResponse

            if [ "$dbUserResponse" = "si" ]; then
                read -p "[Michery] > Introduce la contraseña para el nuevo usuario de la base de datos: " dbPassword
                mysql -e "CREATE USER 'pterodactyluser'@'127.0.0.1' IDENTIFIED BY '$dbPassword';"
                mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'pterodactyluser'@'127.0.0.1' WITH GRANT OPTION;"

                echo "[Michery] > pterodactyluser creado correctamente."

                cd /etc/mysql
                echo "[mysqld]" >> my.cnf
                echo "bind-address=0.0.0.0" >> my.cnf

                echo ""
                echo "[Michery] > my.cnf modificado correctamente."

                echo ""
                echo "–––––––––––––––––– Michery [Databases] –––––––––––––––––––––––––––"
                echo "> Para crear un Database Host en Pterodactyl, sigue estos pasos:"
                echo ""
                echo "[1] > Ve al panel de administración de Pterodactyl."
                echo "[2] > Navega a 'Database Hosts' y crea un nuevo host."
                echo "[3] > Pon el nombre como 'Databases'"
                echo "[4] > Usa '0.0.0.0' para la dirección del host."
                echo "[5] > Utiliza el puerto '3306'."
                echo "[6] > Utiliza 'pterodactyluser' y la contraseña '$dbPassword'."
                echo "[7] > Guarda los cambios."
                echo "––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––"
            fi
                echo ""
                echo "–––––––––––––––––– Michery [Databases] –––––––––––––––––––––––––––"
                echo "> Para crear un Database Host en Pterodactyl, sigue estos pasos:"
                echo ""
                echo "[1] > Ve al panel de administración de Pterodactyl."
                echo "[2] > Navega a 'Database Hosts' y crea un nuevo host."
                echo "[3] > Pon el nombre como 'Databases'"
                echo "[4] > Usa '0.0.0.0' para la dirección del host."
                echo "[5] > Utiliza el puerto '3306'."
                echo "[6] > Utiliza el usuario que hayas creado y la contraseña que hayas establecido."
                echo "[7] > Guarda los cambios."
                echo "––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––"
            ;;
        4)
          read -p "[Michery] > ¿Quieres activar el firewall? (si/no): " firewallResponse

          if [ "$firewallResponse" = "si" ]; then
          # Actualización
          apt update
    
          # Instalar sudo si no está instalado
          apt install -y sudo

          # Instalación UFW
          sudo apt install -y ufw

          # Configurar UFW
          sudo ufw enable
          sudo ufw allow ssh
          sudo ufw default deny incoming
          sudo ufw default allow outgoing
          sudo ufw disable
          sudo ufw enable

          # Permitir puertos específicos
          sudo ufw allow 2375
          sudo ufw allow 2376
          sudo ufw allow 7946
          sudo ufw allow 4789
          sudo ufw allow 80
          sudo ufw allow 8080
          sudo ufw allow 443
          sudo ufw allow 2022
          sudo ufw allow 22
          sudo ufw allow 3306

          clear

          echo "[Michery] > Firewall ha sido creado."

          elif [ "$firewallResponse" = "no" ]; then
              echo "[Michery] > Operación cancelada."
              exit 0
          else
              echo "[Michery] > Respuesta no válida."
              exit 1
          fi

          ;;
        5)
            echo "[Michery] Configuración de SSL"
            apt update
            apt install -y sudo
            sudo apt update
            sudo apt install -y certbot
            sudo apt install -y python3-certbot-nginx
            read -p "[Michery] > Introduce el dominio (panel.): " domain
            certbot certonly --nginx -d "$domain"

            read -p "[Michery] > ¿Quieres también utilizar otro dominio (node.)? (si/no): " otherDomainResponse

            if [ "$otherDomainResponse" = "si" ]; then
                read -p "[Michery] > Introduce el dominio (node.): " nodedomain
                certbot certonly --nginx -d "$nodedomain"
            fi
            ;;
        6)  
            echo ""
            read -p "[Michery] > ¿Quieres crear un usuario para las bases de datos? (si/no): " dbUserResponse

            if [ "$dbUserResponse" = "si" ]; then
                read -p "[Michery] > Introduce la contraseña para el nuevo usuario de la base de datos: " dbPassword
                mysql -e "CREATE USER 'pterodactyluser'@'127.0.0.1' IDENTIFIED BY '$dbPassword';"
                mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'pterodactyluser'@'127.0.0.1' WITH GRANT OPTION;"

                echo "[Michery] > pterodactyluser creado correctamente."

                cd /etc/mysql
                echo "[mysqld]" >> my.cnf
                echo "bind-address=0.0.0.0" >> my.cnf

                echo ""
                echo "[Michery] > my.cnf modificado correctamente."

                echo ""
                echo "–––––––––––––––––– Michery [Databases] –––––––––––––––––––––––––––"
                echo "> Para crear un Database Host en Pterodactyl, sigue estos pasos:"
                echo ""
                echo "[1] > Ve al panel de administración de Pterodactyl."
                echo "[2] > Navega a 'Database Hosts' y crea un nuevo host."
                echo "[3] > Pon el nombre como 'Databases'"
                echo "[4] > Usa '0.0.0.0' para la dirección del host."
                echo "[5] > Utiliza el puerto '3306'."
                echo "[6] > Utiliza 'pterodactyluser' y la contraseña '$dbPassword'."
                echo "[7] > Guarda los cambios."
                echo "––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––"
            fi
                echo ""
                echo "–––––––––––––––––– Michery [Databases] –––––––––––––––––––––––––––"
                echo "> Para crear un Database Host en Pterodactyl, sigue estos pasos:"
                echo ""
                echo "[1] > Ve al panel de administración de Pterodactyl."
                echo "[2] > Navega a 'Database Hosts' y crea un nuevo host."
                echo "[3] > Pon el nombre como 'Databases'"
                echo "[4] > Usa '0.0.0.0' para la dirección del host."
                echo "[5] > Utiliza el puerto '3306'."
                echo "[6] > Utiliza el usuario que hayas creado y la contraseña que hayas establecido."
                echo "[7] > Guarda los cambios."
                echo "––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––"
            ;;
        8)
            echo ""
            echo "[Michery] > Aplicación Finalizada..."
            exit 0
            ;;
        7)
            echo ""
            echo "–––––––––––––––––– Michery [Repair] ––––––––––––––––––––––––––––––"
            echo "> Esto eliminará todos los addons, extensiones, eggs y/o temas" 
            echo "que tengas instalados."
            echo "––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––"
            echo ""

            read -p "[Michery] > ¿Estás seguro de que quieres reparar el panel? (si/no): " userResponse

            if [ "$userResponse" = "si" ]; then
            cd /var/www/pterodactyl
            php artisan down
            rm -r /var/www/pterodactyl/resources
            curl -L https://github.com/pterodactyl/panel/releases/latest/download/panel.tar.gz | tar -xzv
            chmod -R 755 storage/* bootstrap/cache
            composer install --no-dev --optimize-autoloader
            php artisan view:clear
            php artisan config:clear
            php artisan migrate --seed --force
            chown -R www-data:www-data /var/www/pterodactyl/*
            php artisan queue:restart
            php artisan up
            echo ""
            echo "[Michery] > Reparación completada."
            else
                echo ""
                echo "[Michery] > Operación cancelada."
                exit 1
            fi
          ;;    
        *)
            echo ""
            echo "[Michery] > Opción no válida."
            ;;
    esac
done