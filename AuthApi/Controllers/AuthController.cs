using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using AuthApi.Data;
using AuthApi.DTOs;
using AuthApi.Services;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly ITokenService _tokenService;

    public AuthController(
        AppDbContext context,
        ITokenService tokenService)
    {
        _context = context;
        _tokenService = tokenService;
    }

    [HttpGet("test")]
    public IActionResult Test()
    {
        return Ok("AuthController funcionando");
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.Name))
            return BadRequest(new { message = "Nome é obrigatório." });

        if (string.IsNullOrWhiteSpace(dto.Email))
            return BadRequest(new { message = "Email é obrigatório." });

        if (string.IsNullOrWhiteSpace(dto.Password))
            return BadRequest(new { message = "Password é obrigatória." });

        if (dto.Password.Length < 6)
            return BadRequest(new
            {
                message = "A password deve ter pelo menos 6 caracteres."
            });

        var existingUser = await _context.Users
            .FirstOrDefaultAsync(x => x.Email == dto.Email);

        if (existingUser != null)
            return Conflict(new
            {
                message = "Este email já está registado."
            });

        var user = new Models.User
        {
            Name = dto.Name.Trim(),
            Email = dto.Email.Trim().ToLower(),
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password)
        };

        _context.Users.Add(user);

        await _context.SaveChangesAsync();

        return Created($"/api/auth/user/{user.Id}", new
        {
            message = "Usuário registado com sucesso.",
            user.Id,
            user.Name,
            user.Email
        });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.Email))
            return BadRequest(new
            {
                message = "Email é obrigatório."
            });

        if (string.IsNullOrWhiteSpace(dto.Password))
            return BadRequest(new
            {
                message = "Password é obrigatória."
            });

        var user = await _context.Users
            .FirstOrDefaultAsync(x =>
                x.Email == dto.Email);

        if (user == null)
            return Unauthorized(new
            {
                message = "Email ou password inválidos."
            });

        bool valid = BCrypt.Net.BCrypt.Verify(
            dto.Password,
            user.PasswordHash);

        if (!valid)
            return Unauthorized(new
            {
                message = "Email ou password inválidos."
            });

        var token = _tokenService.GenerateToken(user);

        return Ok(new
        {
            message = "Usuário autenticado com sucesso.",
            token
        });
    }


    [Authorize]
    [HttpGet("users")]
    public async Task<IActionResult> GetUsers()
    {
        var users = await _context.Users
            .Select(u => new
            {
                u.Id,
                u.Name,
                u.Email
            })
            .ToListAsync();

        return Ok(users);
    }

    [Authorize]
    [HttpGet("user/{id}")]
    public async Task<IActionResult> GetUser(int id)
    {
        var user = await _context.Users
            .FindAsync(id);

        if (user == null)
            return NotFound(new
            {
                message = "Usuário não encontrado."
            });

        return Ok(new
        {
            user.Id,
            user.Name,
            user.Email
        });
    }


    [Authorize]
    [HttpGet("user/email/{email}")]
    public async Task<IActionResult> GetUserByEmail(string email)
    {
        var user = await _context.Users
            .FirstOrDefaultAsync(u => u.Email == email);

        if (user == null)
            return NotFound();

        return Ok(new
        {
            user.Id,
            user.Name,
            user.Email
        });
    }


    [Authorize]
    [HttpPut("user/{id}")]
    public async Task<IActionResult> UpdateUser(
    int id,
    UpdateUserDto dto)
    {
        var user = await _context.Users
            .FindAsync(id);

        if (user == null)
            return NotFound(new
            {
                message = "Usuário não encontrado."
            });

        user.Name = dto.Name;
        user.Email = dto.Email;

        await _context.SaveChangesAsync();

        return Ok(new
        {
            message = "Usuário atualizado com sucesso."
        });
    }


    [Authorize]
    [HttpPut("user/{id}/password")]
    public async Task<IActionResult> ChangePassword(
    int id,
    ChangePasswordDto dto)
    {
        var user = await _context.Users.FindAsync(id);

        if (user == null)
            return NotFound(new
            {
                message = "Usuário não encontrado."
            });

        if (string.IsNullOrWhiteSpace(dto.CurrentPassword))
            return BadRequest(new { message = "Password é obrigatória." });

        if (dto.NewPassword.Length < 6)
            return BadRequest(new
            {
                message = "A password deve ter pelo menos 6 caracteres."
            });


        bool valid = BCrypt.Net.BCrypt.Verify(
            dto.CurrentPassword,
            user.PasswordHash);

        if (!valid)
            return BadRequest(new
            {
                message = "Password atual incorreta."
            });

        user.PasswordHash =
            BCrypt.Net.BCrypt.HashPassword(dto.NewPassword);

        await _context.SaveChangesAsync();

        return Ok(new
        {
            message = "Password alterada com sucesso."
        });
    }


    [Authorize]
    [HttpDelete("user/{id}")]
    public async Task<IActionResult> DeleteUser(int id)
    {
        var user = await _context.Users
            .FindAsync(id);

        if (user == null)
            return NotFound(new
            {
                message = "Usuário não encontrado."
            });

        _context.Users.Remove(user);

        await _context.SaveChangesAsync();

        return Ok(new
        {
            message = "Usuário removido com sucesso."
        });
    }
}