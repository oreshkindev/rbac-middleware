# RBAC middleware

RBAC расшифровывается как «Role-Based Access Control». Это подход к ограничению доступа к системе для авторизованных пользователей. В системе RBAC права доступа назначаются не непосредственно отдельным пользователям, а ролям, которые могут быть у пользователей. Эти роли представляют собой набор привилегий или прав доступа, которые определяют, какие действия пользователь может выполнять в системе или приложении.

Например, типичные роли в организации могут включать:

- `superuser`: Имеет полный доступ ко всем ресурсам и может управлять другими пользователями и их ролями.

- `manager`: Имеет доступ к определенному набору ресурсов, необходимых для выполнения своих должностных обязанностей.

- `guest`: Имеет очень ограниченный доступ, например, доступ к публичной информации только для чтения.

RBAC позволяет администраторам легче управлять доступом к системе, назначая и переназначая роли, а не устанавливая разрешения для каждого пользователя в отдельности. Это делает модель масштабируемой и гибкой, особенно в крупных организациях.

## Установка

```bash
go get -u github.com/oreshkindev/rbac-middleware
```

### Использование

```go
import (
    "github.com/oreshkindev/rbac-middleware"
)
```

Настройте секретный ключ для JWT:

```go
os.Setenv("SECRET_KEY", "ваш секретный ключ")
```

или используйте окружение .env.sh

```bash
export SECRET_KEY="ваш секретный ключ"
```

или доверьтесь openssl

```bash
export SECRET_KEY="$(openssl rand -base64 32)"
```

Определите роли:

```go
const (
	superuser   string = "superuser"
	manager     string = "manager"
	guest       string = "guest"
)
```

или

```go
const (
    superuser int64 = iota + 1
    manager
    guest
)
```

Используй мидлварь в своем HTTP хендлере:

```go
http.Handle("/lk", rbac.Middleware(superuser)(ваш хендлер))
```

или

```go
router := chi.NewRouter()

router.With(rbac.Middleware(superuser)).Post("/", ваш хендлер)
```

Создание токена:

```go
token, err := rbac.Hash(map[string]interface{}{
		"email":      c.Email,
		"permission": c.PermissionID,
	}, timeout)
```

или

```go
type Claims struct {
    Email string `json:"email"`
    PermissionID int64 `json:"permission"`
}

func (c Claims) ToClaims() map[string]interface{} {
    return map[string]interface{}{
        "email": c.Email,
        "permission": c.PermissionID,
    }
}

token, err := rbac.Hash(UserClaims{Email: "example@...", PermissionID: 1}, timeout)
```
