# RBAC middleware

RBAC stands for "Role-Based Access Control". It is an approach to restricting system access to authorized users. In an RBAC system, permissions are not assigned directly to individual users, but to roles that users can have. These roles represent a set of privileges or access rights that define what actions a user can perform within a system or application.

For example, typical roles in an organization might include:

`superuser`: Has full access to all resources and can manage other users and their roles.
`manager`: Has access to a specific set of resources necessary to perform their job functions.
`guest`: Has very limited access, such as read-only access to public information.

RBAC allows administrators to manage system access more easily by assigning and reassigning roles, rather than setting permissions for each user individually. This makes the model scalable and flexible, especially in large organizations.

## Roles

- `superuser` – allows access to read, modify and delete.
- `manager` – allows access to read and modify.
  ...

## Install

```bash
go get -u github.com/oreshkindev/rbac-middleware
```

## Example

The following example shows how to manage HTTP endpoints access based on roles with this library.

```go
import (
	"net/http"

	"github.com/go-chi/chi/v5"
    "github.com/oreshkindev/rbac-middleware"
)

// Subject - the structure we put in the ‘sub’ field when creating a JWT token.
type Subject struct {
	...
    // Role - is a field that must be necessarily present in the JWT subject.
    // The value of this field is the role of the user for whom access will be granted.
	Role  string `json:"role"`
}

// Define roles
const (
	superuser Access = "superuser"
	manager   Access = "manager"
)

// Example of how to use Rbac middleware
func main() {
	// Any method to create JWT-token with claims
	token, err := rbac.HashToken(Subject{Email: "a@a.com", Role: superuser}, 1)
	if err != nil {
		fmt.Println(err)
	}

    // Use https://jwt.io/ to make sure the body is properly shaped.
	fmt.Println(token)

	// Create router
	router := chi.NewRouter()

	// Create Rbac middleware with access levels for role "superuser"
	router.With(rbac.Guard([]Access{superuser})).Get("/users", func(w http.ResponseWriter, r *http.Request) {
		// Handle GET request
		render.JSON(w, r, map[string]string{"message": "Welcome to Saint-Tropez"})
	})

	http.ListenAndServe(":9000", router)
}

```

Or

```golang
	router.Route("/v1", func(r chi.Router) {
		r.Mount("/post", router.PostHandler())
	})

    func (router *Router) PostHandler() chi.Router {
        r := chi.NewRouter()

        controller := router.manager.Post.PostController

        r.With(rbac.Guard([]Rule{superuser, manager})).Post("/", controller.Create)
        r.Get("/", controller.Find)
        r.Get("/{id}", controller.First)
        r.With(rbac.Guard([]Rule{superuser, manager})).Put("/{id}", controller.Update)
        r.With(rbac.Guard([]Rule{superuser})).Delete("/{id}", controller.Delete)

	    return r
    }
```
