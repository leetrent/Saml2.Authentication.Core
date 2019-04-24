using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using DemoWebApp.Models;

namespace DemoWebApp.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            // Customize the ASP.NET Identity model and override the defaults if needed.
            // For example, you can rename the ASP.NET Identity table names and more.
            // Add your customizations after calling base.OnModelCreating(builder);

            //////////////////////////////////////////////////////////////////////////////////////////
            // Application User (AspNetUsers table):
            //////////////////////////////////////////////////////////////////////////////////////////
            //  - This is being done to fix the following problem:
            //  - "No coercion operator is defined between types 'System.Int16' and 'System.Boolean'"
            //  - This problem was encountered when attempting to seed the database after
            //  - migrating from PostgreSQL to MySQL
            //////////////////////////////////////////////////////////////////////////////////////////
            builder.Entity<ApplicationUser>(au =>
            {
                au.Property(u => u.EmailConfirmed).HasColumnType("tinyint(1)");
                au.Property(u => u.PhoneNumberConfirmed).HasColumnType("tinyint(1)");
                au.Property(u => u.TwoFactorEnabled).HasColumnType("tinyint(1)");
                au.Property(u => u.LockoutEnabled).HasColumnType("tinyint(1)");
            });
        }
    }
}
