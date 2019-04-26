# RBAC - Role Based Access Control Library for Golang ![status](https://img.shields.io/badge/status-alpha-red.svg)

**Heavily** based on Kubernetes RBAC principles.

## Design Concepts

As an example to base the concepts of this library around, let's assume
one wants to use RBAC to authorize users of a blogging platform. Said
platform is capable of providing users access to blogs, blog posts, and
their account details.

* A policy defines a set of resources, resource names, and verbs that
  together allow access to **something**.
  * Resources are arbitrary, but are usually designed around URL
    endpoints. Examples include `blogs, posts/joe, accounts/details`.
  * Resource names are arbitrary as well, but are usually designed
    around data names/types. Examples include a unique name associated
    with an account or tags associated with posts.
  * Verbs are also arbitrary, but are usually mapped to HTTP verbs.
    Examples include `list, get, create, update, patch, delete`.

Here's an example definition of a policy (in YAML):

```yaml
resources:
- blogs
resourceNames:
- "*"
verbs:
- list
- get
```

Policy entries of "*" indicate total access. So in the example above,
this policy grants access to all blogs, but only for listing them and
viewing their details.

In addition to "*", resource names can also contain wildcards. For
example, a resource name of "tech-*" would mean only blogs with names
starting with "tech-" would be accessible via this policy.

* A role is a collection of multiple policies that together define how a
  user can access **things**. For example, a blog admin would have total
  control over all of a specific blog's settings and would be able to
  delete blog posts for their specific blog.

Here's an example definition of a role for an admin of the "rbac" blog
(in YAML again):

```yaml
name: Blog Admin
policies:
- resources:
  - blogs
  resourceNames:
  - rbac
  verbs:
  - "*"
- resources:
  - blogs/posts
  resourceNames:
  - "*"
  verbs:
  - "delete"
```

Here's an example of how this role could get applied in a Go HTTP server
for this blog:

```go
// GET /blogs
func GetBlogs(w http.ResponseWriter, r *http.Request) {
  user := r.Context().Value("user").(string)

  if !rbac.AllowedForUser(user, "blogs", "list") {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
  }

  blogs := GetBlogs()

  var allowed []Blog
  for _, blog := range blogs {
    if rbac.AllowedForUser(user, "blogs", "list", blog.Name) {
      allowed = append(allowed, blog)
    }
  }

  marshalled, _ := json.Marshal(allowed)
  w.Write(marshalled)
}

// GET /blogs/{{blog}}
func GetBlog(w http.ResponseWriter, r *http.Request) {
  var (
    user = r.Context().Value("user").(string)
    vars = mux.Vars(r)
    name = vars["blog"]
  )

  if !rbac.AllowedForUser(user, "blogs", "get", name) {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
  }

  blog := GetBlog(name)

  marshalled, _ := json.Marshal(blog)
  w.Write(marshalled)
}

// PATCH /blogs/{{blog}}
func UpdateBlog(w http.ResponseWriter, r *http.Request) {
  var (
    user = r.Context().Value("user").(string)
    vars = mux.Vars(r)
    name = vars["blog"]
  )

  if !rbac.AllowedForUser(user, "blogs", "patch", name) {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
  }

  data, _ := ioutil.ReadAll(r.Body)
  blog := UpdateBlog(name, data)

  marshalled, _ := json.Marshal(blog)
  w.Write(marshalled)
}

// DELETE /blogs/{{blog}}/posts/{{post}}
func GetBlog(w http.ResponseWriter, r *http.Request) {
  var (
    user = r.Context().Value("user").(string)
    vars = mux.Vars(r)
    blog = vars["blog"]
    name = vars["post"]
  )

  // Ensure user has access to parent blog for this post. The verb used here
  // doesn't have to be the same as the verb used when checking access to the
  // post. Here we're enforcing the requirement that the user at least be able
  // to update the parent blog. This all comes down to how policies and verbs
  // are defined when building roles. For example, one could make up a `control`
  // verb that is required for a blog before taking any actions on posts
  // belonging to the blog.
  if !rbac.AllowedForUser(user, "blogs", "update", blog) {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
  }

  if !rbac.AllowedForUser(user, "blogs/posts", "delete", name) {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
  }

  DeletePost(name)

  w.WriteHeader(http.StatusNoContent)
}
```

Roles are bound to users, and analyzed each time the user tries to
access a resource. The same role can be bound to multiple users, and
users can be bound to multiple roles.
