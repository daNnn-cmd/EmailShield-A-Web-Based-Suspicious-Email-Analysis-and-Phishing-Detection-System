using EmailShield.Models;
using EmailShield.Services;

namespace EmailShield.Data;

public static class DbInitializer
{
    public static void SeedDemoUsers(EmailShieldDbContext context)
    {
        try
        {
            var roles = context.UserRoles.ToList();
            if (roles.Count == 0) return;

            var adminRoleId = roles.FirstOrDefault(r => r.RoleName == "Administrator")?.RoleId ?? 1;
            var analystRoleId = roles.FirstOrDefault(r => r.RoleName == "Security Analyst")?.RoleId ?? 2;
            var viewerRoleId = roles.FirstOrDefault(r => r.RoleName == "Viewer/User")?.RoleId ?? 3;

            bool changed = false;

            if (!context.Users.Any(u => u.Email == "admin@emailshield.local"))
            {
                context.Users.Add(new User
                {
                    FullName = "Administrator (Lead)",
                    Email = "admin@emailshield.local",
                    PasswordHash = PasswordHelper.HashPassword("Admin123!"),
                    RoleId = adminRoleId,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow
                });
                changed = true;
            }

            if (!context.Users.Any(u => u.Email == "analyst@emailshield.local"))
            {
                context.Users.Add(new User
                {
                    FullName = "Daniel Pelpinosas (Security Analyst)",
                    Email = "analyst@emailshield.local",
                    PasswordHash = PasswordHelper.HashPassword("Analyst123!"),
                    RoleId = analystRoleId,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow
                });
                changed = true;
            }

            if (!context.Users.Any(u => u.Email == "viewer@emailshield.local"))
            {
                context.Users.Add(new User
                {
                    FullName = "Faculty / Staff Member (Viewer)",
                    Email = "viewer@emailshield.local",
                    PasswordHash = PasswordHelper.HashPassword("Viewer123!"),
                    RoleId = viewerRoleId,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow
                });
                changed = true;
            }

            if (changed)
            {
                context.SaveChanges();
            }
        }
        catch
        {
            // Database might not be immediately reachable during offline tests; handled gracefully.
        }
    }
}

