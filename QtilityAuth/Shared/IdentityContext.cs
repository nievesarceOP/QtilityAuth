using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace QtilityAuth.Server.Data
{
    public class IdentityContext : IdentityDbContext<User, Role, long>
    {
        public IdentityContext(DbContextOptions options) : base(options)
        {
            
        }
    }
}
