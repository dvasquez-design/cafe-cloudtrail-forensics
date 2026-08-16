# Bitácora — Despliegue del lab "Café CloudTrail Forensics" en Floci

**Objetivo de la sesión:** correr en Floci (emulador local de AWS) el lab de forense
`cafe-cloudtrail-forensics`, originalmente escrito para AWS real.

---

## 1. Revisión y adaptación inicial del repo

Se subió el `.zip` del proyecto. Antes de tocar nada se revisó `README.md` y el
template `infra/cloudformation/cafe-lab-stack.yaml` para entender qué recursos
usa (S3, CloudTrail, Glue/Athena, IAM, EC2, Security Group) y se consultó la
documentación de Floci (`floci.io/floci/services/ec2/`) para detectar puntos de
fricción antes de deployar.

Se identificaron y corrigieron 3 incompatibilidades de entrada:

| Problema original | Ajuste aplicado |
|---|---|
| `ImageId` usaba `{{resolve:ssm:...}}` (parámetro público real de AWS) | Cambiado al alias nativo del catálogo EC2 de Floci |
| `AWS::EC2::KeyPair` sin `PublicKeyMaterial` → Floci genera una clave privada *dummy*, no usable para SSH real | Se agregó el parámetro `PublicKeyMaterial` para forzar un `ImportKeyPair` con la clave pública real del usuario |
| UserData asumía `aws cli` preinstalado | Se agregó instalación explícita del cliente |

Se generó `params.floci.json` de ejemplo y se empaquetó el repo adaptado.

## 2. Preparar la clave SSH

```bash
cat ~/.ssh/id_rsa.pub
```

El usuario ya tenía una clave generada. Se inyectó su contenido en
`params.floci.json` (más adelante se migró a pasarla directo por
`--parameter-overrides`, ver punto 4).

## 3. Primer intento de deploy

```bash
aws cloudformation deploy \
  --template-file cafe-lab-stack.yaml \
  --stack-name cafe-cloudtrail-forensics \
  --parameter-overrides file://params.floci.json \
  --capabilities CAPABILITY_IAM \
  --region us-east-1
```

**Error:**
```
Parameter validation failed:
Invalid type for parameter [0], value: OrderedDict(...), type: <class 'collections.OrderedDict'>, valid types: <class 'str'>
```

**Causa:** `--parameter-overrides` de `aws cloudformation deploy` no acepta el
formato de lista `[{"ParameterKey":..., "ParameterValue":...}]` (ese formato es
para `create-stack`/`update-stack`). Necesita `Key=Value` shorthand o un mapa
simple `{"Key":"Value"}`.

**Fix:** se cambió a shorthand en la línea de comando:

```bash
PUBKEY=$(cat ~/.ssh/id_rsa.pub)
aws cloudformation deploy \
  --template-file cafe-lab-stack.yaml \
  --stack-name cafe-cloudtrail-forensics \
  --parameter-overrides \
    KeyPairName=cafe-lab-key \
    InstanceType=t3.micro \
    "PublicKeyMaterial=${PUBKEY}" \
  --capabilities CAPABILITY_IAM \
  --region us-east-1
```

✅ Funcionó — stack creado.

## 4. Outputs con valores sin resolver

```bash
aws cloudformation describe-stacks --stack-name cafe-cloudtrail-forensics \
  --query 'Stacks[0].Outputs' --output table
```

Dos outputs (`WebServerPublicIp`, `KeyPairId`) devolvieron el texto literal de
la referencia (`CafeWebServer.PublicIp`) en vez del valor real — un `!GetAtt`
que Floci no resuelve en la sección `Outputs` para esos atributos puntuales.
Se resolvió consultando los valores directo por API en vez de por output:

```bash
aws ec2 describe-instances --filters "Name=tag:Name,Values=Cafe Web Server" \
  --query 'Reservations[].Instances[].{ID:InstanceId,Estado:State.Name,IP:PublicIpAddress}' --output table
```

`PublicIpAddress` siempre devuelve `127.0.0.1` en Floci — es esperado (stub de
IMDS), el acceso real es vía puerto publicado en el host.

## 5. Base y tabla Glue no aparecían

CloudFormation marcó `CafeCloudTrailGlueDatabase`/`Table` como
`CREATE_COMPLETE`, pero:

```bash
aws glue get-databases
# {"DatabaseList": []}
```

**Causa:** gap conocido en algunas integraciones CloudFormation↔servicio de
los emuladores — el motor de CFN marca el recurso como creado sin completar
necesariamente la llamada real al servicio subyacente.

**Fix (workaround):** crear la base y tabla directo por API de Glue, con el
mismo nombre/esquema que definía el template (`cafe_cloudtrail_forensics` /
`cloudtrail_logs_monitoring`, con partition projection sobre `region`/`date`).

## 6. Puerto 80 nunca se publicaba

El Security Group abre el puerto 80 a `0.0.0.0/0`, así que Floci debía
publicarlo automáticamente vía un sidecar `socat`. Nunca apareció:

```bash
docker ps --filter "name=floci-ec2-" --format "table {{.Names}}\t{{.Ports}}"
# solo aparecía el puerto 2200 (SSH)
```

## 7. Conflicto de red Docker (endpoint fantasma)

```
WARN Could not connect container ... to network bridge: Status 403:
{"message":"endpoint with name floci-ec2-i-... already exists in network bridge"}
```

**Causa:** un endpoint huérfano de un intento anterior quedó registrado en la
red `bridge` de Docker y bloqueaba que el contenedor nuevo se conectara.

**Fix:**
```bash
docker network disconnect -f bridge floci-ec2-i-<id-viejo>
```

## 8. Sin salida a internet desde los contenedores (causa raíz mayor)

Al reintentar, apareció:
```
Could not install IMDS proxy dependencies ...: Errors during downloading metadata for repository 'amazonlinux'
```

Se aisló el problema paso a paso:

```bash
# 1. Un contenedor genérico, sin Floci de por medio, tampoco tenía salida:
docker run --rm public.ecr.aws/amazonlinux/amazonlinux:2023 sh -c "curl -sI https://cdn.amazonlinux.com --max-time 5"
# SIN CONECTIVIDAD

# 2. ip_forward sí estaba habilitado:
cat /proc/sys/net/ipv4/ip_forward   # → 1

# 3. ufw estaba activo, con "Default: deny (routed)" y sin reglas para docker0

# 4. Docker no tenía NINGUNA regla de NAT:
sudo iptables -t nat -L POSTROUTING -n -v
# 0 packets, 0 bytes en todas las cadenas
```

**Causa raíz real:** `/etc/docker/daemon.json` tenía `"iptables": false` — Docker
tenía deshabilitada explícitamente la gestión de sus propias reglas de NAT, así
que nunca insertó el `MASQUERADE` que los contenedores necesitan para salir a
internet.

**Fix:**
```bash
sudo sed -i 's/"iptables": false/"iptables": true/' /etc/docker/daemon.json
sudo systemctl restart docker
```

Confirmado con:
```bash
sudo iptables -t nat -L POSTROUTING -n -v | grep -i masquerade
```

Y validado con conectividad real desde un contenedor de prueba (`curl -v`
mostró handshake TLS completo contra `cdn.amazonlinux.com`, solo un 403 de
CloudFront ajeno a la red).

## 9. Pérdida de estado por falta de persistencia

Al reiniciar Floci (`floci stop --remove` / `floci start`) para aplicar los
fixes anteriores, el stack completo desapareció:

```bash
aws cloudformation describe-stacks --stack-name cafe-cloudtrail-forensics
# Stack ... does not exist
```

**Causa:** la imagen de Floci arranca en modo `memory` (todo en RAM) por
defecto, sin importar el modo `hybrid` que documentan como default de la
config interna.

**Fix:** activar persistencia explícita:
```bash
mkdir -p ~/floci-data
floci start --persist ~/floci-data
```

(Nota: al limpiar `~/floci-data` en un reset posterior, hizo falta `sudo rm -rf`
porque Floci escribe esos archivos como `root` dentro del contenedor.)

## 10. Conflicto de paquetes en Amazon Linux 2023 (`curl` vs `curl-minimal`)

Con la red ya sana, reapareció el fallo del proxy IMDS, ahora con motivo claro:

```
Could not install IMDS proxy dependencies ...: d by curl-8.17.0-1.amzn2023.0.3.x86_64 from amazonlinux
```

```bash
docker exec <container> sh -c "rpm -q curl curl-minimal"
# package curl is not installed
# curl-minimal-8.17.0-1.amzn2023.0.3.x86_64
```

**Causa:** conflicto de paquetes típico de imágenes recientes de AL2023, donde
`curl-minimal` (preinstalado) choca con el paquete `curl` completo que Floci
intenta instalar para el proxy IMDS (`socat`/`iproute`).

**Fix elegido:** cambiar de AMI en vez de pelear con el conflicto — se migró el
template de `ami-amazonlinux2023` a `ami-ubuntu2404` (alias también soportado
por el catálogo de Floci), reescribiendo el `UserData` de `dnf`/`httpd`/
`ec2-user` a `apt`/`apache2`/`ubuntu`.

## 11. Nuevo error: arquitectura incompatible

```
The architecture 'arm64' of the specified image does not match the
architecture supported by instance type 't3.micro'.
```

**Causa:** el alias `ami-ubuntu2404` del catálogo de Floci resuelve a una
imagen **arm64**, incompatible con `t3.micro` (familia Intel/AMD x86_64).

**Fix:** cambiar `InstanceType` a la familia Graviton/ARM equivalente:
```yaml
InstanceType:
  Default: t4g.micro
  AllowedValues: [t4g.micro, t3.micro, t2.micro]
```

## 12. Usuario IAM `chaos` huérfano

Un intento fallido anterior dejó un usuario IAM sin limpiar:

```
User with name chaos already exists.
```

**Fix:** borrar manualmente la access key y el usuario antes de reintentar:
```bash
aws iam delete-access-key --user-name chaos --access-key-id <id>
aws iam delete-user --user-name chaos
```

## 13. `aws cloudformation deploy` no soportado por Floci

```
An error occurred (UnknownAction) when calling the GetTemplateSummary
operation: Action GetTemplateSummary is not supported.
```

**Causa:** el comando de alto nivel `deploy` llama internamente a
`GetTemplateSummary`, una acción de la API de CloudFormation que Floci todavía
no implementa.

**Fix:** usar los comandos de bajo nivel, que no dependen de esa acción:
```bash
aws cloudformation create-stack \
  --stack-name cafe-cloudtrail-forensics \
  --template-body file://cafe-lab-stack.yaml \
  --parameters \
    ParameterKey=KeyPairName,ParameterValue=cafe-lab-key \
    ParameterKey=InstanceType,ParameterValue=t4g.micro \
    ParameterKey=PublicKeyMaterial,ParameterValue="${PUBKEY}" \
  --capabilities CAPABILITY_IAM \
  --region us-east-1

aws cloudformation wait stack-create-complete --stack-name cafe-cloudtrail-forensics --region us-east-1
```

✅ Stack creado con éxito (`exit code 0`). Instancia `running`, AMI y tipo
correctos (`ami-ubuntu2404` / `t4g.micro`).

## 14. Estado actual: UserData no se ejecuta

Pese a todo lo anterior resuelto, el log sigue mostrando:

```
UserData for EC2 instance i-... did not contain executable shellscript parts
```

Y dentro del contenedor no hay ni `/var/www/html/cafe/` ni `systemctl`
(la imagen Ubuntu usada corre con `tail -f /dev/null`, sin `systemd` activo —
lo cual también implica que `apache2` nunca se habría iniciado por
`systemctl enable/start` aunque el UserData sí se hubiera ejecutado).

**Decisión tomada:** en vez de seguir depurando el mecanismo de UserData de
Floci, se pasa a instalar/configurar el sitio y las credenciales manualmente
dentro del contenedor vía `docker exec`, replicando a mano los mismos pasos
que el UserData intentaba automatizar.

---

## 15. Instalación manual — Apache

Con la decisión de abandonar el UserData automático, se entró directo al
contenedor:

```bash
docker exec floci-ec2-i-6cafe586947c1c3a4 sh -c "cat /etc/os-release; ps aux | head -5; which apt systemctl service"
```

Confirmó Ubuntu 24.04 real, sin `systemd` (proceso 1 = `tail -f /dev/null`,
sin `systemctl`) — hay que usar `service` para manejar Apache.

```bash
docker exec floci-ec2-i-6cafe586947c1c3a4 sh -c "apt-get update -y && apt-get install -y apache2 awscli"
```

**Error:** `Package 'awscli' has no installation candidate` — el paquete de
sistema (v1) no está disponible en esta imagen mínima. Se instaló Apache solo
por apt, y AWS CLI aparte, con el instalador oficial v2.

## 16. Arquitectura real del contenedor vs. metadata del catálogo Floci

Primer intento de instalar AWS CLI v2 con el paquete `aarch64` (asumiendo ARM,
porque CloudFormation había exigido `t4g.micro` por "arquitectura arm64" del
AMI):

```
./aws/install: 78: /tmp/aws/dist/aws: Exec format error
```

**Causa:** el contenedor real es **x86_64** (todos los `.deb` bajados fueron
`amd64`) — desajuste entre lo que el catálogo de Floci declaró como
arquitectura del AMI (`arm64`, lo que forzó el cambio a `t4g.micro` en el
punto 11) y la plataforma real del contenedor Docker (la nativa del host).

**Fix:**
```bash
docker exec floci-ec2-i-6cafe586947c1c3a4 uname -m   # → x86_64
# reinstalar con el paquete x86_64 del AWS CLI v2
curl -s 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o /tmp/awscliv2.zip
```
✅ `aws-cli/2.36.24` instalado y funcionando.

## 17. Apache no arrancaba: puerto 80 "en uso"

```bash
docker exec floci-ec2-i-6cafe586947c1c3a4 service apache2 start
# (98)Address already in use: AH00072: make_sock: could not bind to address 0.0.0.0:80
```

Se revisó qué ocupaba el puerto:
```bash
netstat -tlnp | grep :80
# 169.254.169.254:80  socat (proxy IMDS interno de Floci)
```

**Causa real:** el kernel de Linux no permite que un bind a IP específica
(`169.254.169.254:80`, del `socat` de IMDS) y un bind *wildcard*
(`0.0.0.0:80`, lo que pide Apache por defecto) convivan en el mismo puerto —
se consideran superpuestos aunque las IPs sean distintas.

**Fix:** apuntar Apache a la IP específica del contenedor en vez del wildcard:
```bash
sed -i 's/^Listen 80/Listen 172.17.0.3:80/' /etc/apache2/ports.conf
service apache2 start
```
✅ Apache arriba, sirviendo `200 OK` en `172.17.0.3:80`.

## 18. Bucket de assets vacío — el sitio no estaba en ningún lado accesible

```bash
aws s3 ls s3://cafe-lab-assets-000000000000-us-east-1/site/ --recursive
# (vacío)
```

Se buscó la carpeta `site/` original del repo, que no estaba en el directorio
de trabajo actual:
```bash
find ~ -type d -iname "site" 2>/dev/null | grep -i cafe
# apareció solo en ~/.local/share/Trash/files/... (papelera)
```

**Fix:** se subió el contenido directo desde la papelera:
```bash
aws s3 cp ~/.local/share/Trash/files/cafe-cloudtrail-forensics/site/ \
  s3://cafe-lab-assets-000000000000-us-east-1/site/ --recursive
```

Se detectó además que la estructura real es `site/cafe/index.html` (con
subcarpeta `cafe/` extra), distinto de lo que asumía el UserData original
(`site/index.html` directo) — se ajustó la ruta al copiar hacia el contenedor
para no duplicar el anidado:

```bash
docker exec floci-ec2-i-6cafe586947c1c3a4 sh -c "
mkdir -p /var/www/html/cafe &&
aws s3 cp s3://cafe-lab-assets-000000000000-us-east-1/site/cafe/ /var/www/html/cafe/ --recursive
"
```
✅ Archivos (`index.html` + imágenes) copiados correctamente.

## 19. Confirmar que el sitio responde

```bash
docker exec floci-ec2-i-6cafe586947c1c3a4 curl -sI http://172.17.0.3/cafe/
curl -sI http://172.17.0.3:80/cafe/   # desde el host, directo a la IP interna de Docker
```
✅ `200 OK` en ambos casos.

## 20. Publicar el puerto hacia el navegador

Como Floci nunca llegó a publicar el puerto 80 automáticamente (ver punto 6),
se armó el publishing a mano.

**Primer intento fallido:** sidecar Docker compartiendo namespace de red:
```bash
docker run -d --name floci-ec2-...-http-proxy \
  --network container:floci-ec2-i-6cafe586947c1c3a4 \
  alpine/socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:172.17.0.3:80
```
No sirve para publicar hacia el host (`--network container:` no admite `-p`).
Se descartó y se limpió el contenedor de sobra.

**Fix real:** `socat` corriendo directo en el host, apuntando a la IP interna
del contenedor Docker:
```bash
nohup socat TCP-LISTEN:8080,fork,reuseaddr TCP:172.17.0.3:80 > /tmp/socat-cafe.log 2>&1 &
curl -sI http://localhost:8080/cafe/
```
✅ `200 OK` — sitio accesible en `http://localhost:8080/cafe/` desde el
navegador. Confirmado visualmente por el usuario.

---

## Resumen de causas raíz — actualizado

1. Formato de parámetros de `deploy` vs `create-stack` (uso de CLI, no de Floci).
2. Outputs con `GetAtt` no resueltos para algunos atributos puntuales (gap de Floci).
3. `AWS::Glue::Database/Table` vía CloudFormation no llega a la API real (gap de Floci).
4. Endpoints huérfanos en la red `bridge` de Docker tras intentos fallidos (estado local).
5. **Docker con `"iptables": false`** → sin NAT → sin internet en contenedores (config del host, causa raíz mayor).
6. Floci en modo `memory` por defecto → se pierde todo estado al reiniciar (falta de flag `--persist`).
7. Conflicto de paquetes `curl`/`curl-minimal` en la imagen AL2023 que usa Floci (gap/bug de Floci).
8. Alias `ami-ubuntu2404` resuelve a arm64 (según metadata), incompatible con instancias x86_64 según CloudFormation (gap de catálogo de Floci).
9. `GetTemplateSummary` no implementado → `deploy` de alto nivel falla (gap de Floci).
10. UserData nunca se ejecutó en ningún intento de toda la sesión (causa no diagnosticada a fondo — se resolvió reproduciendo los pasos a mano).
11. Contenedor real corre en la arquitectura nativa del host (x86_64), pese a que el catálogo de Floci había declarado `arm64` para forzar `t4g.micro` — desajuste metadata vs. plataforma real de Docker.
12. Bind de IP wildcard (`0.0.0.0`) y bind de IP específica en el mismo puerto no coexisten a nivel de kernel — interactúa mal con el `socat` interno de IMDS de Floci si el propio servicio de la instancia también pide el puerto 80 en wildcard.
13. Los assets del sitio (`site/`) no estaban en el working directory del usuario — quedaron en la papelera tras una reorganización de carpetas anterior a esta sesión (causa externa al lab/Floci).
14. Estructura real de `site/` con subcarpeta `cafe/` no coincidía con la ruta que asumía el `UserData` original del template.
15. Floci nunca publicó el puerto 80 vía su sidecar `socat` interno pese al Security Group abierto — se resolvió publicándolo manualmente con `socat` en el host, apuntando a la IP interna del contenedor Docker.

## 21. Vulnerabilidad confirmada: credenciales hardcodeadas

Se recuperó la access key de `chaos` desde los outputs del stack (única forma
de ver la secret key generada por CloudFormation) y se escribió a mano dentro
de la instancia, ya que el UserData nunca llegó a hacerlo:

```bash
aws cloudformation describe-stacks --stack-name cafe-cloudtrail-forensics \
  --query 'Stacks[0].Outputs[?OutputKey==`ChaosAccessKeyId` || OutputKey==`ChaosSecretAccessKey`]'

docker exec floci-ec2-i-6cafe586947c1c3a4 sh -c "
mkdir -p /home/ubuntu/.aws &&
cat > /home/ubuntu/.aws/credentials << 'EOC'
[default]
aws_access_key_id = AKIAKUG8WBROHTD9W5H1
aws_secret_access_key = ya80IFlrS//6snZqXXXTeUMMAsPsF251kDZOFEFa
EOC
chown -R ubuntu:ubuntu /home/ubuntu/.aws && chmod 600 /home/ubuntu/.aws/credentials
"
```
✅ Vulnerabilidad central del lab inyectada: credenciales de larga duración en
texto plano, en vez de un IAM Role temporal (contraste con `CafeInstanceRole`,
que sí existe en el stack, bien acotado a solo-lectura del bucket de assets).

## 22. Screenshots de evidencia — plan acordado

Se definió con el usuario una lista acotada de 5-6 capturas clave en vez de un
registro exhaustivo:
1. Sitio funcionando (estado normal) — ✅ tomado.
2. Stack desplegado, todos los recursos `CREATE_COMPLETE` — ✅ tomado
   (`describe-stack-resources`).
3. Credenciales de `chaos` encontradas por SSH — pendiente al momento de
   escribir este punto, tomado en el paso 24.
4. Sitio comprometido (imagen `-hacked.jpg`) — tomado en el paso 27.
5. Evento en CloudTrail / consulta Athena — pendiente, próxima sesión.
6. *(opcional)* Contraste IAM Role acotado vs. policy over-permissive de `chaos`.

## 23. Falta `sshd` en la imagen — SSH real no funcionaba

Al intentar conectar:
```bash
ssh -i ~/.ssh/id_rsa -o StrictHostKeyChecking=no ubuntu@localhost -p 2200
# Connection closed by ::1 port 2200
```

Diagnóstico dentro del contenedor:
```bash
docker exec floci-ec2-i-6cafe586947c1c3a4 sh -c "ps aux | grep ssh; which sshd; cat /home/ubuntu/.ssh/authorized_keys"
# sin sshd, sin authorized_keys
```

**Causa:** la imagen Ubuntu 24.04 mínima que usa Floci no trae `openssh-server`
preinstalado (a diferencia de Amazon Linux). El mecanismo de Floci que inyecta
la clave pública en `authorized_keys` depende del mismo flujo de arranque que
nunca terminó de correr (UserData), así que tampoco se disparó.

**Fix:** instalación manual:
```bash
docker exec floci-ec2-i-6cafe586947c1c3a4 sh -c "
apt-get install -y openssh-server &&
mkdir -p /home/ubuntu/.ssh &&
echo '<clave pública>' > /home/ubuntu/.ssh/authorized_keys &&
chown -R ubuntu:ubuntu /home/ubuntu/.ssh && chmod 700 /home/ubuntu/.ssh && chmod 600 /home/ubuntu/.ssh/authorized_keys &&
service ssh start
"
```
✅ SSH conectó correctamente (con passphrase de la clave local pedida por el
propio cliente SSH, no relacionado a Floci). **[sesión cortada acá por límite
de contexto — retomada en sesión nueva]**

## 24. Fase de ataque simulado (sesión siguiente)

**Paso 1 — abrir SSH al mundo** (genera el evento CloudTrail central a
investigar después):
```bash
aws ec2 authorize-security-group-ingress \
  --group-id sg-26db8dbe28e6cd189 \
  --protocol tcp --port 22 --cidr 0.0.0.0/0 --region us-east-1
```
✅ Regla agregada (`sgr-4c74dce5525e4d410`).

**Paso 2 — entrar por SSH y encontrar las credenciales:**
```bash
ssh -i ~/.ssh/id_rsa ubuntu@localhost -p 2200
cat ~/.aws/credentials
```
✅ Confirmado — screenshot #3 tomado.

## 25. Escalada — usar las credenciales robadas desde afuera del host

```bash
aws configure --profile chaos-attacker
# Access Key / Secret Key / us-east-1 / json
```

**Error:** al principio se corrió `aws configure` sin `--profile`, pisando el
perfil `default` (el de trabajo normal, `test`/`test`) con las credenciales de
`chaos`.

**Fix:**
```bash
aws configure set aws_access_key_id test --profile default
aws configure set aws_secret_access_key test --profile default
aws configure set region us-east-1 --profile default
```

Con el perfil `chaos-attacker` bien separado:
```bash
eval $(floci env)
aws sts get-caller-identity --profile chaos-attacker
```
✅ Confirmado — operando como `chaos` sin necesidad de seguir conectado por SSH.

## 26. Alcance real de la vulnerabilidad — policy over-permissive

```bash
aws iam get-user-policy --user-name chaos --policy-name cafe-lab-INJECTED-overpermissive-ec2 --profile default
```
→ `{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}` — admin total de
EC2 sobre toda la cuenta, no solo la instancia comprometida.

## 27. Revisión del script de referencia (`simulate_hack.py`)

Se leyó el script original del repo para alinear la simulación real con el
guion pensado por el lab. Nota: ese script opera sobre la **versión simulada**
(archivos JSON de estado local, `state/*.json`), no sobre AWS real — se usó
solo como referencia de qué artefactos representar, adaptando cada paso a
acciones reales contra Floci.

## 28. Defacement del sitio

```bash
docker exec floci-ec2-i-6cafe586947c1c3a4 sh -c "
cp /var/www/html/cafe/images/Coffee-and-Pastries.jpg /var/www/html/cafe/images/Coffee-and-Pastries.backup &&
cp /var/www/html/cafe/images/Coffee-and-Pastries-hacked.jpg /var/www/html/cafe/images/Coffee-and-Pastries.jpg
"
```
✅ Confirmado visualmente en `http://localhost:8080/cafe/` — screenshot #4.

## 29. Demostración del pivote de cuenta

```bash
aws ec2 describe-instances --profile chaos-attacker \
  --query 'Reservations[].Instances[].{ID:InstanceId,Nombre:Tags[?Key==`Name`]|[0].Value}' --output table
```
✅ `chaos` lista instancias de toda la cuenta usando la key robada — prueba el
alcance del `ec2:*`, más allá del host original comprometido.

## 30. Corte de sesión — pendientes

Con persistencia activa (`~/floci-data`), el stack y todo su estado quedan
guardados entre reinicios de Floci. Pendiente para la próxima sesión:
- Investigación forense con Athena/CloudTrail (`investigation-real/`) → evento
  `AuthorizeSecurityGroupIngress` y acciones de `chaos` → screenshot #5.
- Remediación: revocar access key de `chaos`, cerrar el SG, restaurar el sitio.
- Documentos finales `.md`: versión Floci del lab + versión AWS real.

---

## 31. Investigación forense — CloudTrail no capturaba eventos

Sesión siguiente. Se intentó el atajo `02_cli_lookup_events_real.sh`:
```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress
# vacío
```

Diagnóstico progresivo:
- `describe-trails` mostró `TrailNotFoundException` para el nombre de ayer
  (`CafeTrail-75e7bdf2`) — otro caso del gap ya visto con Glue: CloudFormation
  marca `CREATE_COMPLETE` pero el servicio real nunca lo tuvo.
- Se recreó el trail manualmente por API (`create-trail` + `start-logging`),
  con los mismos parámetros del template (`monitor`, sin multi-región,
  `IncludeGlobalServiceEvents: true`).
- Pese al trail activo (`IsLogging: true`) y con `EventSelectors` explícitos
  (`ReadWriteType: All`), nunca llegó ni un solo archivo al bucket de logs, ni
  `lookup-events` devolvió nada, ni siquiera tras un reinicio completo de
  Floci y esperar el ciclo de flush (`flushIntervalSeconds=60`).

**Diagnóstico final:** se confirmó vía búsqueda en el repo de Floci que el
`CloudTrailLogWriter` inicia (`floci logs` lo confirma) pero nunca vuelca
nada — comportamiento consistente con un gap real de la versión instalada
(Server 1.6.0, confirmado vía `floci version`, más reciente que todo lo
documentado en las release notes públicas al momento de esta sesión). No es
un problema de configuración nuestra.

## 32. Workaround — evento de CloudTrail generado a mano

Se construyó un registro CloudTrail con el formato JSON real de AWS (mismo
schema que usaría un archivo de log genuino), comprimido en `.gz`, y subido a
la ruta exacta que espera la tabla Glue (partition projection por
`region`/`date`):

```bash
gzip -c evento.json > 000000000000_CloudTrail_us-east-1_20260816T2300Z_manual.json.gz
aws s3 cp 000000000000_CloudTrail_us-east-1_20260816T2300Z_manual.json.gz \
  s3://cafe-lab-monitoring-000000000000-us-east-1/AWSLogs/000000000000/CloudTrail/us-east-1/2026/08/16/
```
✅ Subido correctamente — screenshot #5 preparado desde acá.

## 33. Segundo gap — Athena/Glue no sincronizan en Floci

Intento de consulta Athena:
```bash
aws athena start-query-execution --query-string "SELECT ... FROM cafe_cloudtrail_forensics.cloudtrail_logs_monitoring ..."
```
**Error:** `Catalog Error: schema "cafe_cloudtrail_forensics" does not exist`.

Se probó pasando la base vía `--query-execution-context Database=...` en vez
de en el `FROM` — mismo resultado, ahora `Table with name
cloudtrail_logs_monitoring does not exist!`.

**Causa confirmada:** el motor DuckDB interno de Floci (`floci-duck`, usado
para Athena) no está sincronizado con la tabla Glue creada manualmente por
API en el punto 6 de esta bitácora — mismo patrón de gap Glue↔servicio visto
antes, ahora afectando la integración Glue↔Athena específicamente.

**Decisión:** abandonar Athena para esta investigación y leer el log crudo
directo desde S3:
```bash
aws s3 cp s3://cafe-lab-monitoring-.../000000000000_CloudTrail_..._manual.json.gz - | zcat | python3 -m json.tool
```
✅ Evento completo visible: `AuthorizeSecurityGroupIngress`, `userName: chaos`,
`accessKeyId`, `sourceIPAddress: 203.0.113.55`, `userAgent`. Screenshot #5
tomado.

**Decisión de producto (pendiente para el cierre):** no eliminar Athena/Glue
del proyecto. El template está bien escrito; el gap es de esta versión
puntual de Floci. Se documentará como limitación conocida en la versión Floci
del lab, manteniendo el código intacto para la versión AWS real (donde si
va a funcionar sin problemas).

## 34. Remediación — cierre del incidente

Siguiendo `scripts/remediate_real.sh` como guía, paso a paso:

```bash
# 1. Revocar la regla SSH abierta
aws ec2 revoke-security-group-ingress --group-id sg-26db8dbe28e6cd189 \
  --protocol tcp --port 22 --cidr 0.0.0.0/0 --region us-east-1
```
✅ `{"Return": true}`

```bash
# 2. Desactivar y borrar la access key comprometida
aws iam update-access-key --user-name chaos --access-key-id AKIAKUG8WBROHTD9W5H1 --status Inactive
aws iam delete-access-key --user-name chaos --access-key-id AKIAKUG8WBROHTD9W5H1
aws iam list-access-keys --user-name chaos
```
✅ Lista vacía — key eliminada correctamente.

**Verificación con gap adicional:** al confirmar que `chaos-attacker` ya no
podía operar, `aws sts get-caller-identity --profile chaos-attacker` **no**
devolvió el error esperado (`InvalidClientTokenId`) — en su lugar, Floci
devolvió una identidad `root` implícita (`arn:aws:iam::000000000000:root`) y
el perfil siguió pudiendo listar instancias EC2. **Gap de fidelidad de auth
de Floci**: ante credenciales inválidas/borradas, cae a un fallback
permisivo en vez de rechazar la request como AWS real. La remediación del
lado de IAM es correcta y completa (verificado por `list-access-keys` vacío);
la falla es exclusivamente de cómo Floci maneja el caso de credenciales
faltantes.

```bash
# 3. Restaurar el sitio y limpiar las credenciales del host
docker exec floci-ec2-i-6cafe586947c1c3a4 sh -c "
cp /var/www/html/cafe/images/Coffee-and-Pastries.backup /var/www/html/cafe/images/Coffee-and-Pastries.jpg &&
rm -f /home/ubuntu/.aws/credentials
"
```

**Obstáculo encontrado:** el contenedor de la instancia se había detenido
solo 23 minutos antes (causa no determinada — posiblemente relacionado a los
comandos de remediación de IAM/SG, o a un timeout interno de Floci). Al
reiniciarlo con `docker start`, Docker le asignó una **IP interna nueva**
(`172.17.0.4`, antes `172.17.0.3`), rompiendo tanto el bind de Apache
(`ports.conf` seguía apuntando a la IP vieja) como el `socat` del host que
publicaba el puerto 8080.

**Fix:**
```bash
docker exec floci-ec2-i-6cafe586947c1c3a4 sh -c "sed -i 's/172.17.0.3:80/172.17.0.4:80/' /etc/apache2/ports.conf && service apache2 start"
pkill -f "socat TCP-LISTEN:8080"
nohup socat TCP-LISTEN:8080,fork,reuseaddr TCP:172.17.0.4:80 > /tmp/socat-cafe.log 2>&1 &
```

**Falso positivo final:** tras el fix, el navegador seguía mostrando la
imagen hackeada — no era un problema real, sino **cache del navegador**.
Confirmado comparando hashes en el servidor:
```bash
md5sum Coffee-and-Pastries.jpg Coffee-and-Pastries.backup Coffee-and-Pastries-hacked.jpg
# .jpg y .backup con hash idéntico, distinto al -hacked.jpg -> restauración correcta
```
✅ Confirmado visualmente por el usuario tras hard refresh (`Ctrl+Shift+R`).

## Checklist final de remediación

| Ítem | Estado |
|---|---|
| Regla SG `0.0.0.0/0:22` revocada | ✅ |
| Access key de `chaos` desactivada y borrada | ✅ |
| Credenciales en texto plano eliminadas del host | ✅ |
| Sitio restaurado a la imagen original | ✅ |
| Gap de auth de Floci con credenciales inválidas | ⚠️ documentado, no accionable desde el lab |

---

## Resumen de causas raíz — final

*(continúa del resumen anterior, puntos 16-19 agregados)*

16. `CloudTrailLogWriter` de Floci nunca entrega logs a S3 pese a trail activo
    y event selectors explícitos — gap de la versión instalada (Server 1.6.0),
    no reproducible por configuración de nuestro lado.
17. Motor DuckDB de Athena en Floci no sincroniza con tablas Glue creadas por
    API — mismo patrón de gap Glue↔servicio visto el día 1, ahora en la
    integración Glue↔Athena.
18. Floci no rechaza `sts:get-caller-identity` con credenciales borradas —
    cae a una identidad `root` implícita en vez de `InvalidClientTokenId`,
    afectando la fidelidad de las pruebas de remediación de IAM.
19. Reinicio de un contenedor Docker detenido le asigna una IP interna nueva,
    rompiendo cualquier configuración que la referencie de forma hardcodeada
    (Apache `ports.conf`, `socat` del host) — comportamiento estándar de
    Docker, no de Floci, pero relevante para cualquier fix manual hecho en
    esta sesión que dependa de la IP interna del contenedor.

## Estado final

✅ Lab completo: instalación → deploy → ataque simulado → evidencia forense
(vía workaround) → remediación verificada.

**Pendiente para el cierre:**
- Decidir el tratamiento de Athena/Glue en la versión Floci del proyecto
  (mantener código, documentar como no-funcional en esta versión de Floci).
- Armar `.md` final versión Floci (con todos los ajustes/workarounds de esta
  bitácora incorporados como guía reproducible).
- Armar `.md` versión AWS real (sin los workarounds — el template original
  funciona tal cual contra una cuenta real).

## Anexo — comandos usados para retomar la sesión de un día para otro

*(referencia histórica del corte de sesión entre el día 1 y el día 2)*

```bash
# 1. Arrancar Floci con la persistencia de ayer
floci start --persist ~/floci-data
eval $(floci env)
floci status

# 2. Confirmar que el stack sigue vivo
aws cloudformation describe-stacks --stack-name cafe-cloudtrail-forensics \
  --region us-east-1 --query 'Stacks[0].StackStatus' --output text

# 3. Confirmar que la instancia EC2 volvió a levantar
#    (el contenedor Docker de la instancia puede necesitar un restart aparte,
#    ya que floci start no arranca automáticamente los ec2 containers previos)
aws ec2 describe-instances --filters "Name=tag:Name,Values=Cafe Web Server" \
  --query 'Reservations[].Instances[].{ID:InstanceId,Estado:State.Name}' --output table

docker ps -a --filter "name=floci-ec2-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# 4. Si el contenedor de la instancia no está corriendo, reiniciarla:
aws ec2 start-instances --instance-ids i-6cafe586947c1c3a4 --region us-east-1
sleep 15
docker ps --filter "name=floci-ec2-" --format "table {{.Names}}\t{{.Ports}}"

# 5. Volver a levantar Apache y sshd manualmente (no persisten dentro del
#    propio contenedor si Docker lo recrea desde cero -- si el container ID
#    es el mismo que ayer, probablemente sigan corriendo solos)
docker exec floci-ec2-i-6cafe586947c1c3a4 sh -c "service apache2 status; service ssh status"
#    si no están corriendo:
docker exec floci-ec2-i-6cafe586947c1c3a4 sh -c "service apache2 start; service ssh start"

# 6. Volver a levantar el socat del host (NO persiste, es un proceso del SO,
#    no de Floci -- seguro hay que rehacer esto):
ps aux | grep socat
#    si no aparece:
nohup socat TCP-LISTEN:8080,fork,reuseaddr TCP:172.17.0.3:80 > /tmp/socat-cafe.log 2>&1 &
curl -sI http://localhost:8080/cafe/

# 7. Confirmar que el perfil chaos-attacker sigue configurado
aws sts get-caller-identity --profile chaos-attacker
```

**Ojo:** si en el paso 6 la IP interna del contenedor (`172.17.0.3`) cambió
respecto a ayer, hay que consultarla de nuevo antes de correr `socat`:
```bash
docker inspect floci-ec2-i-6cafe586947c1c3a4 --format '{{.NetworkSettings.IPAddress}}'
```


