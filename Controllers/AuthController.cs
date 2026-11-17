using EmailShield.Data;
using EmailShield.DTOs;
using EmailShield.Models;
using EmailShield.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EmailShield.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly EmailShieldDbContext _context;

    public AuthController(EmailShieldDbContext context)
    {
        _context = context;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            return BadRequest(new { message = "Email and password are required." });

        var user = await _context.Users
            .Include(u => u.Role)
            .FirstOrDefaultAsync(u => u.Email.ToLower() == request.Email.ToLower());

        if (user == null || !PasswordHelper.VerifyPassword(request.Password, user.PasswordHash))
        {
            return Unauthorized(new { message = "Invalid email or password." });
        }

        if (!user.IsActive)
        {
            return Unauthorized(new { message = "Your account has been deactivated. Please contact an administrator." });
        }

        // Add Audit Log
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.UserId,
            Action = "USER_LOGIN",
            Description = $"User {user.FullName} ({user.Role.RoleName}) logged in successfully.",
            Ipaddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1",
            CreatedAt = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();

        // Set secure session cookie for server-side anti-forced browsing route protection
        Response.Cookies.Append("EmailShield_Session", user.UserId.ToString(), new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = true,
            Path = "/"
        });

        return Ok(new UserResponse
        {
            UserId = user.UserId,
            FullName = user.FullName,
            Email = user.Email,
            RoleId = user.RoleId,
            RoleName = user.Role.RoleName,
            IsActive = user.IsActive,
            CreatedAt = user.CreatedAt
        });
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        Response.Cookies.Delete("EmailShield_Session", new CookieOptions { Path = "/" });
        return Ok(new { message = "Logged out successfully." });
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password) || string.IsNullOrWhiteSpace(request.FullName))
            return BadRequest(new { message = "Full name, email, and password are required." });

        bool exists = await _context.Users.AnyAsync(u => u.Email.ToLower() == request.Email.ToLower());
        if (exists)
            return BadRequest(new { message = "A user with this email address already exists." });

        var role = await _context.UserRoles.FindAsync(request.RoleId) 
            ?? await _context.UserRoles.FirstOrDefaultAsync(r => r.RoleName == "Viewer/User");

        if (role == null)
            return BadRequest(new { message = "Invalid role specified." });

        var newUser = new User
        {
            FullName = request.FullName.Trim(),
            Email = request.Email.Trim().ToLower(),
            PasswordHash = PasswordHelper.HashPassword(request.Password),
            RoleId = role.RoleId,
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };

        _context.Users.Add(newUser);
        await _context.SaveChangesAsync();

        _context.AuditLogs.Add(new AuditLog
        {
            UserId = request.AdminUserId ?? newUser.UserId,
            Action = "USER_CREATED",
            Description = $"New user account created for {newUser.FullName} ({newUser.Email}) with role {role.RoleName}.",
            Ipaddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1",
            CreatedAt = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();

        return Ok(new UserResponse
        {
            UserId = newUser.UserId,
            FullName = newUser.FullName,
            Email = newUser.Email,
            RoleId = newUser.RoleId,
            RoleName = role.RoleName,
            IsActive = newUser.IsActive,
            CreatedAt = newUser.CreatedAt
        });
    }

    [HttpPost("users")]
    public async Task<IActionResult> CreateUser([FromBody] RegisterRequest request)
    {
        return await Register(request);
    }

    [HttpGet("roles")]
    public async Task<IActionResult> GetRoles()
    {
        var roles = await _context.UserRoles
            .OrderBy(r => r.RoleId)
            .Select(r => new RoleResponse
            {
                RoleId = r.RoleId,
                RoleName = r.RoleName,
                Description = r.Description
            })
            .ToListAsync();

        return Ok(roles);
    }

    [HttpGet("users/{id}")]
    public async Task<IActionResult> GetUserById(int id)
    {
        var user = await _context.Users
            .Include(u => u.Role)
            .FirstOrDefaultAsync(u => u.UserId == id);

        if (user == null) return NotFound(new { message = "User not found." });

        return Ok(new UserResponse
        {
            UserId = user.UserId,
            FullName = user.FullName,
            Email = user.Email,
            RoleId = user.RoleId,
            RoleName = user.Role.RoleName,
            IsActive = user.IsActive,
            CreatedAt = user.CreatedAt
        });
    }

    [HttpPut("users/{id}")]
    public async Task<IActionResult> UpdateUser(int id, [FromBody] UpdateUserRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.FullName) || string.IsNullOrWhiteSpace(request.Email))
            return BadRequest(new { message = "Full name and email are required." });

        var user = await _context.Users.Include(u => u.Role).FirstOrDefaultAsync(u => u.UserId == id);
        if (user == null) return NotFound(new { message = "User not found." });

        bool emailTaken = await _context.Users.AnyAsync(u => u.UserId != id && u.Email.ToLower() == request.Email.Trim().ToLower());
        if (emailTaken)
            return BadRequest(new { message = "This email is already registered to another user." });

        var role = await _context.UserRoles.FindAsync(request.RoleId);
        if (role == null)
            return BadRequest(new { message = "Invalid role specified." });

        user.FullName = request.FullName.Trim();
        user.Email = request.Email.Trim().ToLower();
        user.RoleId = role.RoleId;
        user.IsActive = request.IsActive;

        if (!string.IsNullOrWhiteSpace(request.Password))
        {
            user.PasswordHash = PasswordHelper.HashPassword(request.Password);
        }

        _context.AuditLogs.Add(new AuditLog
        {
            UserId = request.AdminUserId ?? user.UserId,
            Action = "USER_UPDATED",
            Description = $"User account '{user.FullName}' ({user.Email}) updated to role {role.RoleName}, status {(user.IsActive ? "Active" : "Inactive")}.",
            Ipaddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1",
            CreatedAt = DateTime.UtcNow
        });

        await _context.SaveChangesAsync();

        return Ok(new UserResponse
        {
            UserId = user.UserId,
            FullName = user.FullName,
            Email = user.Email,
            RoleId = user.RoleId,
            RoleName = role.RoleName,
            IsActive = user.IsActive,
            CreatedAt = user.CreatedAt
        });
    }

    [HttpDelete("users/{id}")]
    public async Task<IActionResult> DeleteUser(int id, [FromQuery] int? adminUserId = null)
    {
        var user = await _context.Users.Include(u => u.Role).FirstOrDefaultAsync(u => u.UserId == id);
        if (user == null) return NotFound(new { message = "User not found." });

        if (adminUserId.HasValue && adminUserId.Value == id)
        {
            return BadRequest(new { message = "You cannot delete your own logged-in administrator account." });
        }

        // Guard against deleting the only remaining Administrator
        if (user.RoleId == 1)
        {
            int adminCount = await _context.Users.CountAsync(u => u.RoleId == 1 && u.UserId != id);
            if (adminCount == 0)
            {
                return BadRequest(new { message = "Cannot delete the sole remaining Administrator account." });
            }
        }

        // Unlink audit logs referencing this user to satisfy FK
        var userAuditLogs = await _context.AuditLogs.Where(a => a.UserId == id).ToListAsync();
        foreach (var al in userAuditLogs)
        {
            al.UserId = null;
        }

        // Reassign email samples and generated reports to admin user
        int fallbackAdminId = adminUserId ?? (await _context.Users.Where(u => u.RoleId == 1 && u.UserId != id).Select(u => u.UserId).FirstOrDefaultAsync());
        if (fallbackAdminId != 0)
        {
            var userSamples = await _context.EmailSamples.Where(s => s.UserId == id).ToListAsync();
            foreach (var sample in userSamples)
            {
                sample.UserId = fallbackAdminId;
            }

            var userReports = await _context.GeneratedReports.Where(r => r.GeneratedBy == id).ToListAsync();
            foreach (var rep in userReports)
            {
                rep.GeneratedBy = fallbackAdminId;
            }
        }

        string deletedName = user.FullName;
        string deletedEmail = user.Email;
        string deletedRole = user.Role.RoleName;

        _context.Users.Remove(user);
        await _context.SaveChangesAsync();

        // Write deletion audit log
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = adminUserId,
            Action = "USER_DELETED",
            Description = $"User account '{deletedName}' ({deletedEmail}, Role: {deletedRole}) was permanently deleted by Administrator.",
            Ipaddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1",
            CreatedAt = DateTime.UtcNow
        });
        await _context.SaveChangesAsync();

        return Ok(new { success = true, message = $"User '{deletedName}' deleted successfully." });
    }

    [HttpGet("users")]
    public async Task<IActionResult> GetUsers()
    {
        var users = await _context.Users
            .Include(u => u.Role)
            .OrderByDescending(u => u.CreatedAt)
            .Select(u => new UserResponse
            {
                UserId = u.UserId,
                FullName = u.FullName,
                Email = u.Email,
                RoleId = u.RoleId,
                RoleName = u.Role.RoleName,
                IsActive = u.IsActive,
                CreatedAt = u.CreatedAt
            })
            .ToListAsync();

        return Ok(users);
    }

    [HttpPut("users/{id}/toggle-status")]
    public async Task<IActionResult> ToggleUserStatus(int id)
    {
        var user = await _context.Users.FindAsync(id);
        if (user == null) return NotFound(new { message = "User not found." });

        user.IsActive = !user.IsActive;

        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.UserId,
            Action = "USER_STATUS_CHANGED",
            Description = $"User {user.FullName} status set to {(user.IsActive ? "Active" : "Inactive")}.",
            Ipaddress = "127.0.0.1",
            CreatedAt = DateTime.UtcNow
        });

        await _context.SaveChangesAsync();
        return Ok(new { success = true, isActive = user.IsActive });
    }

    [HttpPost("seed-demo-users")]
    public async Task<IActionResult> SeedDemoUsers()
    {
        var roles = await _context.UserRoles.ToListAsync();
        var adminRole = roles.FirstOrDefault(r => r.RoleName == "Administrator")?.RoleId ?? 1;
        var analystRole = roles.FirstOrDefault(r => r.RoleName == "Security Analyst")?.RoleId ?? 2;
        var viewerRole = roles.FirstOrDefault(r => r.RoleName == "Viewer/User")?.RoleId ?? 3;

        var seeded = new List<string>();

        // 1. Admin
        if (!await _context.Users.AnyAsync(u => u.Email == "admin@emailshield.local"))
        {
            _context.Users.Add(new User
            {
                FullName = "System Administrator",
                Email = "admin@emailshield.local",
                PasswordHash = PasswordHelper.HashPassword("Admin123!"),
                RoleId = adminRole,
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            });
            seeded.Add("admin@emailshield.local");
        }

        // 2. Security Analyst
        if (!await _context.Users.AnyAsync(u => u.Email == "analyst@emailshield.local"))
        {
            _context.Users.Add(new User
            {
                FullName = "Daniel Pelpinosas (Analyst)",
                Email = "analyst@emailshield.local",
                PasswordHash = PasswordHelper.HashPassword("Analyst123!"),
                RoleId = analystRole,
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            });
            seeded.Add("analyst@emailshield.local");
        }

        // 3. Viewer
        if (!await _context.Users.AnyAsync(u => u.Email == "viewer@emailshield.local"))
        {
            _context.Users.Add(new User
            {
                FullName = "Staff Member (Viewer)",
                Email = "viewer@emailshield.local",
                PasswordHash = PasswordHelper.HashPassword("Viewer123!"),
                RoleId = viewerRole,
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            });
            seeded.Add("viewer@emailshield.local");
        }

        if (seeded.Count > 0)
        {
            await _context.SaveChangesAsync();
        }

        return Ok(new
        {
            message = "Demo users checked/seeded successfully.",
            seededAccounts = new[]
            {
                new { role = "Administrator", email = "admin@emailshield.local", password = "Admin123!" },
                new { role = "Security Analyst", email = "analyst@emailshield.local", password = "Analyst123!" },
                new { role = "Viewer/User", email = "viewer@emailshield.local", password = "Viewer123!" }
            }
        });
    }
}
