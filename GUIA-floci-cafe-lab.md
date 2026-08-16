# Guía Floci — Lab "Café CloudTrail Forensics"

**Versión:** adaptada para correr contra [Floci](https://github.com/floci-io/floci) (emulador local de AWS), no contra una cuenta AWS real.

**Estado del lab en esta versión:** ✅ funcional de punta a punta (setup → ataque → evidencia forense → remediación), con 2 workarounds documentados por gaps de Floci (CloudTrail sin delivery real, Athena/Glue sin sincronizar).

---

## 0. Resumen ejecutivo

Este lab simula el compromiso de un servidor web de un café ficticio: un Security Group demasiado permisivo permite acceso SSH, dentro del host quedan credenciales de AWS en texto plano, y esas credenciales se usan para escalar y desfigurar el sitio. La investigación forense reconstruye el ataque vía CloudTrail/Athena, y cierra con la remediación completa.

Corriendo contra **Floci** en vez de AWS real, la infraestructura y el flujo del ataque funcionan igual, pero aparecen algunos gaps del emulador que requieren trabajo manual puntual — documentados abajo, con el fix exacto para cada uno.

**Veredicto de uso:** válido para practicar el flujo completo sin gastar en AWS real, pero con fricción real por los gaps de CloudTrail/Athena — evaluar si conviene seguir usando Floci para este tipo de lab o migrar directo a un sandbox de AWS real (ver documento aparte con los archivos ya listos para eso).

---

## 1. Prerrequisitos

- Docker instalado y corriendo, con `"iptables": true` en `/etc/docker/daemon.json` (revisar — si está en `false`, los contenedores no van a tener salida a internet; cambiarlo y `systemctl restart docker`).
- Si usás `ufw`: agregar reglas de forwarding para `docker0`:
  ```bash
  sudo ufw route allow in on docker0 out on <tu-interfaz-de-red>
  sudo ufw route allow in on <tu-interfaz-de-red> out on docker0
  sudo ufw reload
  ```
- Floci CLI instalado (`curl -fsSL https://floci.io/install.sh | sh`).
- `aws-cli` v2 instalado en el host.
- Una clave SSH real (`~/.ssh/id_rsa` o similar) — Floci no genera claves privadas usables por `AWS::EC2::KeyPair` sin `PublicKeyMaterial`.

---

## 2. Cambios respecto al template original (AWS real)

| Cambio | Motivo |
|---|---|
| `ImageId: ami-ubuntu2404` (en vez de `{{resolve:ssm:...}}` con Amazon Linux) | La SSM dynamic reference no resuelve en Floci; y Amazon Linux 2023 tiene conflicto de paquetes `curl`/`curl-minimal` al instalar dependencias del proxy IMDS |
| `InstanceType: t4g.micro` (en vez de `t3.micro`) | `ami-ubuntu2404` en el catálogo de Floci resuelve a imagen arm64; `t3.micro` es x86_64-only |
| `PublicKeyMaterial` agregado al `AWS::EC2::KeyPair` | Floci genera claves privadas dummy si no se importa una real |
| UserData reescrito a `apt`/`apache2`/usuario `ubuntu` | Antes usaba `dnf`/`httpd`/`ec2-user` (Amazon Linux) |

El archivo completo ya adaptado: **`cafe-lab-stack-floci.yaml`** (compartido en el chat).

---

## 3. Deploy paso a paso

### 3.1 Arrancar Floci con persistencia

```bash
mkdir -p ~/floci-data
floci start --persist ~/floci-data
eval $(floci env)
```

Sin `--persist`, Floci arranca en modo memoria — se pierde todo al reiniciar.

### 3.2 Deployar el stack

`aws cloudformation deploy` **no funciona** en Floci (depende de la acción `GetTemplateSummary`, no implementada). Usar `create-stack`:

```bash
PUBKEY=$(cat ~/.ssh/id_rsa.pub)

aws cloudformation create-stack \
  --stack-name cafe-cloudtrail-forensics \
  --template-body file://cafe-lab-stack-floci.yaml \
  --parameters \
    ParameterKey=KeyPairName,ParameterValue=cafe-lab-key \
    ParameterKey=InstanceType,ParameterValue=t4g.micro \
    ParameterKey=PublicKeyMaterial,ParameterValue="${PUBKEY}" \
  --capabilities CAPABILITY_IAM \
  --region us-east-1

aws cloudformation wait stack-create-complete --stack-name cafe-cloudtrail-forensics --region us-east-1
```

### 3.3 Workaround — crear la base/tabla Glue a mano

CloudFormation marca `AWS::Glue::Database`/`Table` como `CREATE_COMPLETE` pero el servicio real de Glue no los recibe. Crear manualmente:

```bash
aws glue create-database --database-input '{"Name": "cafe_cloudtrail_forensics"}'

aws glue create-table \
  --database-name cafe_cloudtrail_forensics \
  --table-input '{
    "Name": "cloudtrail_logs_monitoring",
    "TableType": "EXTERNAL_TABLE",
    "Parameters": {
      "projection.enabled": "true",
      "projection.region.type": "enum",
      "projection.region.values": "us-east-1",
      "projection.date.type": "date",
      "projection.date.range": "2026/01/01,NOW",
      "projection.date.format": "yyyy/MM/dd",
      "projection.date.interval": "1",
      "projection.date.interval.unit": "DAYS",
      "storage.location.template": "s3://cafe-lab-monitoring-000000000000-us-east-1/AWSLogs/000000000000/CloudTrail/${region}/${date}"
    },
    "StorageDescriptor": {
      "Location": "s3://cafe-lab-monitoring-000000000000-us-east-1/AWSLogs/000000000000/CloudTrail/",
      "InputFormat": "com.amazon.emr.cloudtrail.CloudTrailInputFormat",
      "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
      "SerdeInfo": {"SerializationLibrary": "com.amazon.emr.hive.serde.CloudTrailSerde"},
      "Columns": [
        {"Name": "eventversion", "Type": "string"},
        {"Name": "useridentity", "Type": "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string>"},
        {"Name": "eventtime", "Type": "string"},
        {"Name": "eventsource", "Type": "string"},
        {"Name": "eventname", "Type": "string"},
        {"Name": "awsregion", "Type": "string"},
        {"Name": "sourceipaddress", "Type": "string"},
        {"Name": "useragent", "Type": "string"},
        {"Name": "requestparameters", "Type": "string"},
        {"Name": "responseelements", "Type": "string"}
      ]
    },
    "PartitionKeys": [
      {"Name": "region", "Type": "string"},
      {"Name": "date", "Type": "string"}
    ]
  }'
```

### 3.4 Workaround — recrear el CloudTrail Trail a mano

Mismo gap: el `AWS::CloudTrail::Trail` del template no queda funcional. Recrear:

```bash
aws cloudtrail create-trail \
  --name monitor \
  --s3-bucket-name cafe-lab-monitoring-000000000000-us-east-1 \
  --include-global-service-events \
  --no-is-multi-region-trail \
  --enable-log-file-validation \
  --region us-east-1

aws cloudtrail start-logging --name monitor --region us-east-1

aws cloudtrail put-event-selectors \
  --trail-name monitor \
  --event-selectors '[{"ReadWriteType": "All", "IncludeManagementEvents": true}]' \
  --region us-east-1
```

⚠️ **Este trail nunca llegó a entregar eventos reales durante esta sesión**, ni a `lookup-events` ni al bucket S3, pese a `IsLogging: true`. Ver sección 6 para el workaround de evidencia forense.

### 3.5 Levantar Apache y sshd manualmente

El `UserData` de la instancia **nunca se ejecutó** en ningún intento de esta sesión (log: `did not contain executable shellscript parts`, causa no resuelta). Hacer todo a mano:

```bash
# Averiguar el nombre del contenedor de la instancia:
docker ps --filter "name=floci-ec2-" --format "table {{.Names}}"
# usar ese nombre en los comandos siguientes (INSTANCE_CONTAINER)

INSTANCE_CONTAINER="floci-ec2-i-XXXXXXXXXXXXXXXXX"

# Apache + AWS CLI
docker exec $INSTANCE_CONTAINER sh -c "apt-get update -y && apt-get install -y apache2 curl unzip"
docker exec $INSTANCE_CONTAINER sh -c "
curl -s 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o /tmp/awscliv2.zip &&
cd /tmp && unzip -q awscliv2.zip && ./aws/install
"
# nota: usar el paquete aarch64 si tu instancia resultó ser realmente ARM
# (confirmar antes con: docker exec $INSTANCE_CONTAINER uname -m)

# sshd + tu clave pública
docker exec $INSTANCE_CONTAINER sh -c "
apt-get install -y openssh-server &&
mkdir -p /home/ubuntu/.ssh &&
echo '$(cat ~/.ssh/id_rsa.pub)' > /home/ubuntu/.ssh/authorized_keys &&
chown -R ubuntu:ubuntu /home/ubuntu/.ssh && chmod 700 /home/ubuntu/.ssh && chmod 600 /home/ubuntu/.ssh/authorized_keys &&
service ssh start
"
```

### 3.6 Subir el sitio y arrancar Apache

```bash
aws s3 cp site/cafe/ s3://cafe-lab-assets-000000000000-us-east-1/site/cafe/ --recursive

docker exec $INSTANCE_CONTAINER sh -c "
mkdir -p /var/www/html/cafe &&
aws s3 cp s3://cafe-lab-assets-000000000000-us-east-1/site/cafe/ /var/www/html/cafe/ --recursive
"
```

**Workaround — bind de puerto 80:** el `socat` interno de Floci (proxy IMDS) ocupa `169.254.169.254:80`, y el kernel no permite que Apache bindee `0.0.0.0:80` (wildcard) al mismo tiempo. Hay que apuntar Apache a la IP específica del contenedor:

```bash
CONTAINER_IP=$(docker inspect $INSTANCE_CONTAINER --format '{{.NetworkSettings.IPAddress}}')

docker exec $INSTANCE_CONTAINER sh -c "
sed -i \"s/^Listen 80/Listen ${CONTAINER_IP}:80/\" /etc/apache2/ports.conf &&
service apache2 start
"
```

**Workaround — publicar el puerto hacia el navegador:** Floci nunca publicó el puerto 80 pese al Security Group abierto (otro gap). Publicarlo manualmente con `socat` en el host:

```bash
nohup socat TCP-LISTEN:8080,fork,reuseaddr TCP:${CONTAINER_IP}:80 > /tmp/socat-cafe.log 2>&1 &
curl -sI http://localhost:8080/cafe/
```

El sitio queda accesible en `http://localhost:8080/cafe/`.

⚠️ **Si el contenedor de la instancia se reinicia** (`docker start` tras un `Exited`), Docker le asigna una **IP interna nueva** — hay que repetir el `sed` de `ports.conf` y relanzar el `socat` con la IP actualizada.

### 3.7 Inyectar la vulnerabilidad (credenciales de `chaos`)

```bash
CHAOS_KEYS=$(aws cloudformation describe-stacks --stack-name cafe-cloudtrail-forensics \
  --query 'Stacks[0].Outputs[?OutputKey==`ChaosAccessKeyId` || OutputKey==`ChaosSecretAccessKey`]')
# extraer ChaosAccessKeyId y ChaosSecretAccessKey de ahí

docker exec $INSTANCE_CONTAINER sh -c "
mkdir -p /home/ubuntu/.aws &&
cat > /home/ubuntu/.aws/credentials << 'EOC'
[default]
aws_access_key_id = <ChaosAccessKeyId>
aws_secret_access_key = <ChaosSecretAccessKey>
EOC
chown -R ubuntu:ubuntu /home/ubuntu/.aws && chmod 600 /home/ubuntu/.aws/credentials
"
```

---

## 4. Nota sobre outputs del stack

`WebServerPublicIp` y `KeyPairId` no resuelven en los `Outputs` (quedan como texto literal de la referencia, ej. `CafeWebServer.PublicIp`) — gap de `!GetAtt` en Floci para esos atributos puntuales. Consultar directo:

```bash
aws ec2 describe-instances --filters "Name=tag:Name,Values=Cafe Web Server" \
  --query 'Reservations[].Instances[].{ID:InstanceId,Estado:State.Name}' --output table
```

`PublicIpAddress` de la instancia siempre devuelve `127.0.0.1` (stub de IMDS) — normal en Floci, el acceso real es vía el puerto publicado (sección 3.6).

---

## 5. Fase de ataque

Con la instancia ya lista, seguir el guion normal del lab (ver `README.md` del proyecto):

```bash
# 1. Abrir SSH al mundo (genera el evento a investigar)
aws ec2 authorize-security-group-ingress \
  --group-id <SecurityGroupId> --protocol tcp --port 22 --cidr 0.0.0.0/0 --region us-east-1

# 2. Entrar y encontrar las credenciales
ssh -i ~/.ssh/id_rsa ubuntu@localhost -p 2200
cat ~/.aws/credentials

# 3. Usarlas desde afuera del host (perfil separado, nunca pisar el default)
aws configure --profile chaos-attacker

# 4. Confirmar el alcance (policy over-permissive: ec2:* sobre *)
aws iam get-user-policy --user-name chaos --policy-name cafe-lab-INJECTED-overpermissive-ec2

# 5. Defacement
docker exec $INSTANCE_CONTAINER sh -c "
cp /var/www/html/cafe/images/Coffee-and-Pastries.jpg /var/www/html/cafe/images/Coffee-and-Pastries.backup &&
cp /var/www/html/cafe/images/Coffee-and-Pastries-hacked.jpg /var/www/html/cafe/images/Coffee-and-Pastries.jpg
"

# 6. Pivote de cuenta (prueba del alcance de ec2:*)
aws ec2 describe-instances --profile chaos-attacker --region us-east-1
```

---

## 6. Investigación forense — workaround de CloudTrail/Athena

**Gap confirmado:** ni `lookup-events` ni la entrega a S3 funcionaron en esta versión de Floci (Server 1.6.0), pese a trail activo y event selectors correctos. Tampoco Athena pudo consultar la tabla Glue creada por API (`Catalog Error: schema does not exist`).

**Workaround — generar el registro CloudTrail a mano, en formato real:**

```bash
cat > evento.json << 'EOF'
{
  "Records": [
    {
      "eventVersion": "1.08",
      "userIdentity": {
        "type": "IAMUser", "principalId": "AIDACAFELAB000000001",
        "arn": "arn:aws:iam::000000000000:user/chaos", "accountId": "000000000000",
        "accessKeyId": "<ChaosAccessKeyId>", "userName": "chaos"
      },
      "eventTime": "<timestamp real>",
      "eventSource": "ec2.amazonaws.com",
      "eventName": "AuthorizeSecurityGroupIngress",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "<IP simulada del atacante>",
      "userAgent": "aws-cli/2.x ...",
      "requestParameters": {"groupId": "<SecurityGroupId>", "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}},
      "responseElements": {"requestId": "sim-0001", "_return": true},
      "requestID": "sim-0001", "eventID": "sim-event-0001",
      "readOnly": false, "eventType": "AwsApiCall", "recipientAccountId": "000000000000"
    }
  ]
}
EOF

gzip -c evento.json > 000000000000_CloudTrail_us-east-1_<fecha>_manual.json.gz

aws s3 cp 000000000000_CloudTrail_us-east-1_<fecha>_manual.json.gz \
  s3://cafe-lab-monitoring-000000000000-us-east-1/AWSLogs/000000000000/CloudTrail/us-east-1/<YYYY>/<MM>/<DD>/
```

**Leer la evidencia directo desde S3** (sin depender de Athena, que no sincroniza):

```bash
aws s3 cp s3://cafe-lab-monitoring-000000000000-us-east-1/AWSLogs/000000000000/CloudTrail/us-east-1/<YYYY>/<MM>/<DD>/<archivo>.gz - | zcat | python3 -m json.tool
```

Esto reemplaza la consulta SQL de `investigation-real/01_athena_investigation_real.py` para esta versión Floci — el código de Athena queda intacto en el repo para cuando se corra contra AWS real.

---

## 7. Remediación

```bash
# 1. Cerrar el SSH
aws ec2 revoke-security-group-ingress \
  --group-id <SecurityGroupId> --protocol tcp --port 22 --cidr 0.0.0.0/0 --region us-east-1

# 2. Revocar la access key de chaos
aws iam update-access-key --user-name chaos --access-key-id <ChaosAccessKeyId> --status Inactive
aws iam delete-access-key --user-name chaos --access-key-id <ChaosAccessKeyId>

# 3. Restaurar el sitio y limpiar credenciales del host
docker exec $INSTANCE_CONTAINER sh -c "
cp /var/www/html/cafe/images/Coffee-and-Pastries.backup /var/www/html/cafe/images/Coffee-and-Pastries.jpg &&
rm -f /home/ubuntu/.aws/credentials
"
```

⚠️ **Gap de fidelidad de auth:** tras borrar la access key, `aws sts get-caller-identity --profile chaos-attacker` no falla como en AWS real (`InvalidClientTokenId`) — Floci devuelve una identidad `root` implícita y el perfil sigue pudiendo operar. La remediación de IAM es correcta igual (confirmable con `list-access-keys` vacío); es solo la simulación de "bloqueo" la que no es 100% fiel en Floci.

Si el navegador sigue mostrando el sitio hackeado tras restaurar, es cache — hacer hard refresh (`Ctrl+Shift+R`) antes de sospechar de la restauración.

---

## 8. Comandos para retomar una sesión pausada

```bash
floci start --persist ~/floci-data
eval $(floci env)

aws cloudformation describe-stacks --stack-name cafe-cloudtrail-forensics --query 'Stacks[0].StackStatus' --output text

docker ps -a --filter "name=floci-ec2-" --format "table {{.Names}}\t{{.Status}}"
# si Exited: docker start <nombre>, y repetir el bloque de "IP interna nueva" (sección 3.6)

docker exec $INSTANCE_CONTAINER sh -c "service apache2 status; service ssh status"
# si no están corriendo: service apache2 start; service ssh start (revisar antes ports.conf si cambió la IP)

ps aux | grep socat
# si no aparece: repetir el socat del host con la IP actual del contenedor
```

---

## 9. Gaps de Floci encontrados en esta sesión (resumen)

| # | Gap | Impacto | Workaround |
|---|---|---|---|
| 1 | `aws cloudformation deploy` no soportado (`GetTemplateSummary`) | Deploy de alto nivel falla | Usar `create-stack`/`update-stack` |
| 2 | `AWS::Glue::Database`/`Table` vía CFN no llegan al servicio real | `get-databases` vacío pese a `CREATE_COMPLETE` | Crear por API directo |
| 3 | `AWS::CloudTrail::Trail` vía CFN no queda funcional | Sin trail real | Recrear por API (`create-trail`) |
| 4 | `CloudTrailLogWriter` nunca entrega eventos (ni a S3 ni a `lookup-events`) | Sin evidencia forense real | Generar el log manualmente en formato AWS real y subirlo a S3 |
| 5 | Athena (`floci-duck`) no sincroniza con tablas Glue creadas por API | Consultas SQL fallan | Leer el log crudo directo desde S3 (`zcat`) |
| 6 | `UserData` de EC2 nunca se ejecuta | Sin auto-configuración del servidor | Reproducir cada paso a mano vía `docker exec` |
| 7 | Alias `ami-ubuntu2404` resuelve a arm64, contenedor real corre x86_64 | Confusión de arquitectura al instalar binarios | Usar `uname -m` dentro del contenedor antes de bajar binarios |
| 8 | Bind wildcard (`0.0.0.0`) choca con el `socat` de IMDS en el mismo puerto | Apache no arranca | Apache escuchando en la IP específica del contenedor |
| 9 | Floci no publica el puerto pese al Security Group abierto | Sitio no accesible desde el navegador | `socat` manual en el host |
| 10 | Docker asigna IP nueva al reiniciar un contenedor detenido | Rompe configs hardcodeadas (Apache, socat) | Reconsultar IP y reaplicar tras cada restart |
| 11 | `sts:get-caller-identity` con credenciales borradas no falla, cae a `root` | Remediación de IAM no 100% verificable end-to-end | Verificar por `list-access-keys` en vez de por el fallo esperado |
| 12 | `"iptables": false` en Docker (config del host, no de Floci) rompe la salida a internet de todos los contenedores | Ningún `apt`/`dnf` funciona | `"iptables": true` + reinicio de Docker |

**Conclusión:** para un experimento puntual, corrió — pero la cantidad de workarounds necesarios (12 gaps, varios de ellos centrales al propósito del lab: CloudTrail y Athena son literalmente el corazón de un lab de forense) hace cuestionable seguir invirtiendo tiempo en esta ruta en vez de migrar directo a un sandbox de AWS real, donde el template original funciona sin modificaciones.
