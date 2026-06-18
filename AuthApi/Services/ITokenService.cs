using AuthApi.Models;

namespace AuthApi.Services;

public interface ITokenService

{
    string GenerateToken(User user);
}