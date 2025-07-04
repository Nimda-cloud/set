# NIMDA System - Privileges and Blocking Setup Instructions

## 🔐 **Проблема з паролем**

### **Поточна ситуація:**
- Система використовує поточного користувача `dev` ✅
- Credentials система виправлена ✅
- Реальне блокування додано ✅

### **Що потрібно зробити:**

## 1. **Налаштування sudo доступу**

### **Крок 1: Перевірте sudo права**
```bash
sudo whoami
```
Якщо запитує пароль - введіть пароль користувача `dev`

### **Крок 2: Налаштуйте sudo без пароля (опціонально)**
```bash
# Відкрийте sudoers файл
sudo visudo

# Додайте рядок (замініть 'dev' на вашого користувача):
dev ALL=(ALL) NOPASSWD: ALL
```

### **Крок 3: Перевірте налаштування**
```bash
sudo -n whoami
```
Повинно повернути `root` без запиту пароля

## 2. **Налаштування firewall (pfctl)**

### **Крок 1: Перевірте статус firewall**
```bash
sudo pfctl -s info
```

### **Крок 2: Створіть базову конфігурацію**
```bash
# Створіть файл конфігурації
sudo nano /etc/pf.conf

# Додайте базові правила:
set skip on lo
block drop in proto tcp from any to any port 22
block drop in proto tcp from any to any port 23
```

### **Крок 3: Завантажте правила**
```bash
sudo pfctl -ef /etc/pf.conf
```

## 3. **Тестування системи**

### **Запустіть тест:**
```bash
python3 test_privileges_fix.py
```

### **Очікувані результати:**
```
🔐 Sudo Access: ✅ PASS
🔑 Credentials Verification: ✅ PASS  
🛡️ Firewall Commands: ✅ PASS
👤 PrivilegeManager: ✅ PASS
```

## 4. **Використання в системі**

### **Після налаштування:**
1. **Пароль буде прийматися** - система реально перевіряє sudo доступ
2. **Блокування працюватиме** - IP адреси та порти будуть блокуватися через pfctl
3. **Security policy виконуватиметься** - всі дії будуть реальними

### **Приклади дій:**
- `🚫 Blocking: 104.18.19.125.443` → IP `104.18.19.125` буде заблокований
- `🚫 Blocking: Port 7000` → Порт `7000` буде заблокований
- `🔒 Isolating: suspicious_process` → Процес буде ізольований

## 5. **Перевірка роботи**

### **Перевірте заблоковані IP:**
```bash
sudo pfctl -s rules
```

### **Перевірте заблоковані порти:**
```bash
sudo pfctl -s rules | grep port
```

### **Перевірте логи:**
```bash
sudo pfctl -s info
```

## 6. **Усунення неполадок**

### **Проблема: "Failed to verify privileges"**
**Рішення:** Перевірте sudo права та пароль

### **Проблема: "Firewall commands require privileges"**
**Рішення:** Налаштуйте pfctl та sudo права

### **Проблема: "Block action failed"**
**Рішення:** Перевірте конфігурацію pfctl

## 7. **Безпека**

### **Важливо:**
- Не надавайте NOPASSWD sudo права без потреби
- Регулярно перевіряйте правила firewall
- Моніторте логи на предмет підозрілої активності

### **Рекомендації:**
- Використовуйте часові обмеження для sudo
- Налаштуйте логування всіх привілейованих дій
- Регулярно оновлюйте правила безпеки

## 🎯 **Результат**

Після налаштування система NIMDA буде:
- ✅ Приймати правильний пароль
- ✅ Реально блокувати загрози
- ✅ Виконувати всі security policy дії
- ✅ Працювати з повними привілеями

**Система готова до реального використання!** 🚀 