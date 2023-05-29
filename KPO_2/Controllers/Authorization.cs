using Microsoft.AspNetCore.Mvc;
using System.Xml.Linq;
using KPO_2;
using Microsoft.EntityFrameworkCore;
using System.Text;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace KPO_2.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class Authorization : ControllerBase
    {
        private readonly AppDbContext _context;
        public Authorization(AppDbContext context)
        {
            _context = context;
        }

        private bool CheckEmail(string email)
        {
            int atIndex = email.IndexOf("@");
            if (atIndex >= 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private bool CheckName(string name)
        {
            if (name.Length < 4)
            {
                return false;
            }
            return true;
        }

        private bool CheckPassword(string password)
        {
            if (password.Length < 8)
            {
                return false;
            }
            return true;
        }

        private bool UserEmailExists(string email)
        {
            bool emailExists = _context.user.Any(u => u.email == email);
            return emailExists;
        }

        private bool CheckUserExists(string username, string email)
        {
            bool usernameExists = _context.user.Any(u => u.username == username);
            bool emailExists = _context.user.Any(u => u.email == email);
            return usernameExists || emailExists;
        }

        public static string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] hashBytes = sha256.ComputeHash(passwordBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        [HttpPost("Registration")]
        public IActionResult Registration([FromBody] RegistrationRequest request)
        {
            //TODO make single request check
            if (request == null)
            {
                return BadRequest("Request is null.");
            }
            if (request.Email == null)
            {
                return BadRequest("Email is null.");
            }
            if (request.Name == null)
            {
                return BadRequest("Name is null.");
            }
            if (request.Password == null)
            {
                return BadRequest("Password is null.");
            }
            if (!CheckEmail(request.Email))
            {
                return BadRequest("Email check failed.");
            }
            if (!CheckName(request.Name))
            {
                return BadRequest("Name check failed.");
            }
            if (!CheckPassword(request.Password))
            {
                return BadRequest("Password check failed.");
            }
            if (CheckUserExists(request.Name, request.Email))
            {
                return BadRequest("User already exists.");
            }

            user user = new user();
            user.username = request.Name;
            user.email = request.Email;
            user.role = "customer";
            user.password_hash = HashPassword(request.Password);
            user.created_at = DateTime.UtcNow;
            user.updated_at = DateTime.UtcNow;
            _context.user.Add(user);
            _context.SaveChanges();

            return Ok("Registration successful.");
        }

        private bool UserAlreadyAuthorized(UserAuthorizationRequest request)
        {
            var user = _context.user.FirstOrDefault(u => u.email == request.Email);
            var session = _context.session.FirstOrDefault(u => u.user_id == user.id);
            if (session == null)
            {
                return false;
            }
            DateTime current_time = DateTime.UtcNow;
            DateTime expires_at = session.expires_at;
            if (expires_at < current_time)
            {
                return false;
            }
            return true;
        }

        private bool PasswordCheck(UserAuthorizationRequest request)
        {
            var user = _context.user.FirstOrDefault(u => u.email == request.Email);
            string hashed_password = HashPassword(request.Password);
            if (hashed_password == user.password_hash)
            {
                return true;
            }
            return false;
        }

        [HttpPost("UserAuthorization")]
        public IActionResult UserAuthorization([FromBody] UserAuthorizationRequest request)
        {
            if (request == null)
            {
                return BadRequest("Request is null.");
            }
            if (request.Email == null)
            {
                return BadRequest("Email is null.");
            }
            if (request.Password == null)
            {
                return BadRequest("Password is null.");
            }
            if (!UserEmailExists(request.Email))
            {
                return BadRequest("User not exists.");
            }
            if (UserAlreadyAuthorized(request))
            {
                return BadRequest("User already athorized.");
            }
            if (!PasswordCheck(request))
            {
                return BadRequest("User password incorrect.");
            }

            string secret_key = "POSTAVTE_10_POZHALUYSTA_UMOLYAYU";
            var token_handler = new JwtSecurityTokenHandler();
            var token_desc = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("email", request.Email), }),
                Expires = DateTime.UtcNow.AddHours(2),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret_key)),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = token_handler.CreateToken(token_desc);
            var token_string = token_handler.WriteToken(token);

            var user = _context.user.FirstOrDefault(u => u.email == request.Email);
            var session = _context.session.FirstOrDefault(u => u.user_id == user.id);
            if (session != null)
            {
                session.session_token = token_string;
                session.expires_at = token.ValidTo;
                _context.session.Update(session);
                _context.SaveChanges();
            } else
            {
                session new_session = new session();
                new_session.user_id = user.id;
                new_session.session_token = token_string;
                new_session.expires_at = token.ValidTo;
                _context.session.Add(new_session);
                _context.SaveChanges();
            }

            return Ok(token_string);
        }

        [HttpPut("ChangeRole")]
        public IActionResult ChangeRole([FromBody] ChangeRoleRequest request)
        {
            
            return Ok("Registration successful");
        }


    }
}
