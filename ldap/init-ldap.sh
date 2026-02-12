#!/bin/bash
# LDAP 数据自动初始化脚本

# 等待 LDAP 服务就绪（最多30秒）
for i in {1..15}; do
    if ldapsearch -x -H ldap://localhost -b "dc=secnotes,dc=icu" -D "cn=admin,dc=secnotes,dc=icu" -w admin123 >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

# 检查数据是否已存在
if ldapsearch -x -H ldap://localhost -b "ou=users,dc=secnotes,dc=icu" -D "cn=admin,dc=secnotes,dc=icu" -w admin123 -LLL "(uid=admin)" dn 2>/dev/null | grep -q "^dn:"; then
    echo "Data already exists, skipping initialization"
    exit 0
fi

# 导入初始化数据
echo "Importing LDAP data..."
if ldapadd -x -H ldap://localhost -D "cn=admin,dc=secnotes,dc=icu" -w admin123 -f /ldif/users-data.ldif >/dev/null 2>&1; then
    echo "LDAP data imported successfully"
else
    echo "Failed to import LDAP data"
    exit 1
fi
