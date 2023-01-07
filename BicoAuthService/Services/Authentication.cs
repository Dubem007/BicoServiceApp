using AutoMapper;
using BicoAuthService.Entities;
using BicoAuthService.Entities.DataTransferObjects;
using BicoAuthService.Entities.Identity;
using BicoAuthService.Helpers;
using BicoAuthService.Interface;
using BicoAuthService.Shared;
using BicoAuthService.Shared.Enums;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace BicoAuthService.Services
{
    public class Authentication: IAuthentication
    {
        private readonly IMapper _mapper;
        private readonly IConfiguration _configuration;
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<Role> _roleManager;
        private readonly IUserRepository _userRepository;
        private readonly IToken _token;
        private readonly IWebHelper _webHelper;
        private readonly IUserActivityRepository _userActivityRepository;

        public Authentication(IMapper mapper,
        IConfiguration configuration,
        UserManager<User> userManager,
        RoleManager<Role> roleManager,IToken token, IUserActivityRepository userActivityRepository, IUserRepository userRepository, IWebHelper webHelper)
        {
            _mapper = mapper;
            _configuration = configuration;
            _userManager = userManager;
            _roleManager = roleManager;
            _token = token;
            _userActivityRepository = userActivityRepository;
            _userRepository = userRepository;
            _webHelper = webHelper;
        }

        public async Task<ApiResponse<UserLoginResponse>> Login(UserLoginDTO model)
        {
            var user = await _userManager.FindByNameAsync(model.Email.ToLower().Trim());
            if (user == null)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.WrongEmailOrPassword);

            if (user.Status.Equals(EUserStatus.Disabled.ToString(), StringComparison.OrdinalIgnoreCase))
                throw new RestException(HttpStatusCode.Unauthorized, ResponseMessages.UserIsDisabled);

            if (!user.IsActive || !user.EmailConfirmed || user.Status != EUserStatus.Active.ToString() || !user.IsVerified)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.WrongEmailOrPassword);

            var isUserValid = await _userManager.CheckPasswordAsync(user, model.Password);
            if (!isUserValid)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.WrongEmailOrPassword);

            user.LastLogin = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            UserActivity userActivity = AuditLog.UserActivity(user, user.Id, nameof(user), $"Logged in", user.Id);
            var roles = await _userManager.GetRolesAsync(user);
            await _userActivityRepository.CreateAsync(userActivity);
            await _userActivityRepository.SaveChangesAsync();

            var userViewModel = _mapper.Map<UserLoginResponse>(user);

            var tokenResponse = Authenticate(user, roles);
            userViewModel.AccessToken = tokenResponse.AccessToken;
            userViewModel.ExpiresIn = tokenResponse.ExpiresIn;
            userViewModel.RefreshToken = GenerateRefreshToken(user.Id);

            return new ApiResponse<UserLoginResponse>
            {
                Message = ResponseMessages.LoginSuccessResponse,
                Data = userViewModel
            };
        }

        public async Task<ApiResponse<UserMemberResponseDto>> CreateUserMember(UserMemberCreationInputDto input)
        {
            //var referenceToken = await _token.FirstOrDefaultAsync(x => x.Value == input.ReferenceToken, false);
            //if (referenceToken is null)
            //    throw new RestException(HttpStatusCode.BadRequest, ResponseMessages.InvalidExpiredToken);

            //var isValid = CustomToken.IsTokenValid(referenceToken);
            //if (!isValid)
            //    throw new RestException(HttpStatusCode.NotFound, ResponseMessages.InvalidToken);

            string profilePictureUrl = string.Empty;
            //if (input.ProfileImage != null)
            //    profilePictureUrl = await _awsS3Client.UploadFileAsync(input.ProfileImage);

            var newUser = new User
            {
                UserName = input.Email.ToLower().Trim(),
                Email = input.Email.ToLower().Trim(),
                EmailConfirmed = true,
                FirstName = input.FirstName,
                LastName = input.LastName,
                ImageUrl = profilePictureUrl == "" ? input.FirstName : profilePictureUrl,
                ProfileImage = profilePictureUrl == "" ? input.FirstName : profilePictureUrl,
                PrefferedName = input.PrefferedName,
                DateOfBirth = input.DateOfBirth,
                ProfessionalField = input.ProfessionalField,
                Location = input.Location,
                Bio = input.Bio,
                Country = input.Country,
                IsActive = true,
                IsVerified = true,
                Status = EUserStatus.Active.ToString(),
            };
            newUser.PasswordHash = _userManager.PasswordHasher.HashPassword(newUser, input.Password);
            var result = await _userManager.CreateAsync(newUser, input.Password);
            if (!result.Succeeded)
                throw new RestException(HttpStatusCode.BadRequest, result.Errors.FirstOrDefault().Description);
            await _userManager.AddToRoleAsync(newUser, ERole.Regular.ToString());
           
            //_token.Delete(referenceToken);
            //await _token.SaveChangesAsync();

            var response = _mapper.Map<UserMemberResponseDto>(input);
            response.ProfileImage = profilePictureUrl;
            response.Id = newUser.Id;
            response.CreatedAt = newUser.CreatedAt;

            return new ApiResponse<UserMemberResponseDto>
            {
                Message = ResponseMessages.CreationSuccessResponse,
                Data = response
            };
        }

        public async Task<ApiResponse<UserMemberResponseDto>> UpdateUserMember(UserMemberUpdateInputDto input)
        {
            var userMember = await _userRepository.FindByCondition(x => x.Id == input.UserMemberId, true)
                .FirstOrDefaultAsync();

            if (userMember is null)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.UserNotFound);

            string profilePictureUrl = null;
            //if (input.ProfileImage != null)
            //    profilePictureUrl = await _awsS3Client.UploadFileAsync(input.ProfileImage);
            userMember.Country = input.Country;
            userMember.Location = input.Location;
            _mapper.Map(input, userMember);
            userMember.ImageUrl = profilePictureUrl ?? userMember.ImageUrl;

            _userRepository.Update(userMember);
            await _userRepository.SaveChangesAsync();

            var response = _mapper.Map<UserMemberResponseDto>(userMember);

            return new ApiResponse<UserMemberResponseDto>
            {
                Message = ResponseMessages.CreationSuccessResponse,
                Data = response
            };
        }

        public async Task<ApiResponse<RefreshTokenResponse>> GetRefreshToken(RefreshTokenDTO model)
        {
            var userId = GetUserIdFromAccessToken(model.AccessToken);

            var user = await _userRepository.FirstOrDefaultAsync(x => x.Id == userId, false);
            if (user == null)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.UserNotFound);

            var isRefreshTokenValid = ValidateRefreshToken(model.RefreshToken);
            if (!isRefreshTokenValid)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.InvalidToken);

            var roles = await _userManager.GetRolesAsync(user);
            var tokenResponse = Authenticate(user, roles);

            var newRefreshToken = GenerateRefreshToken(user.Id);

            var tokenViewModel = new RefreshTokenResponse
            {
                AccessToken = tokenResponse.AccessToken,
                RefreshToken = newRefreshToken,
                ExpiresIn = tokenResponse.ExpiresIn
            };

            return new ApiResponse<RefreshTokenResponse>
            {
                Message = ResponseMessages.RetrievalSuccessResponse,
                Data = tokenViewModel
            };
        }

        public async Task<ApiResponse<GetSetPasswordDto>> SetPassword(SetPasswordDTO model)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");

            var token = await _token.FirstOrDefaultAsync(x => x.Value == model.Token, true);
            if (token == null)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.InvalidExpiredToken);

            var isValid = CustomToken.IsTokenValid(token);
            if (!isValid)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.InvalidToken);

            var user = await _userRepository.FirstOrDefaultAsync(x => x.Id == token.UserId, true);
            if (user.Email != model.Email.ToLower().Trim())
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.InvalidToken);

            string profilePictureUrl = string.Empty;
            //if (model.ProfilePicture != null)
               // profilePictureUrl = await _awsS3Client.UploadFileAsync(model.ProfilePicture);

            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, model.Password);
            user.UpdatedAt = DateTime.UtcNow;
            user.ImageUrl = profilePictureUrl;

            if (token.TokenType == ETokenType.RegisterUser.ToString())
            {
                user.IsActive = true;
                user.Status = EUserStatus.Active.ToString();
                user.EmailConfirmed = true;
                user.IsVerified = true;
            }
            _userRepository.Update(user);

            UserActivity userActivity = AuditLog.UserActivity(user, user.Id, nameof(user), $"Signed up", user.Id);
            await _userActivityRepository.CreateAsync(userActivity);

            _token.Delete(token);
            await _token.SaveChangesAsync();
            await _userRepository.SaveChangesAsync();

            return new ApiResponse<GetSetPasswordDto>
            {
                Message = ResponseMessages.PasswordSetSuccessfully,
                Data = _mapper.Map<GetSetPasswordDto>(user)
            };
        }

        public async Task<ApiResponse<object>> ResetPassword(ResetPasswordDTO model)
        {
            var token = await _token.FirstOrDefaultAsync(x => x.Value == model.ReferenceToken, false);
            if (token is null)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.InvalidExpiredToken);

            if (!token.TokenType.Equals(ETokenType.ReferenceToken.ToString(), StringComparison.OrdinalIgnoreCase))
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.InvalidExpiredToken);

            var user = await _userRepository.FirstOrDefaultAsync(x => x.Id == token.UserId, false);
            if (user == null)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.UserNotFound);

            if (DateTime.Now >= token.ExpiresAt)
            {
                _token.Delete(token);
                await _token.SaveChangesAsync();
                await _userRepository.SaveChangesAsync();

                throw new RestException(HttpStatusCode.BadRequest, ResponseMessages.TokenExpired);
            }

            user.PasswordHash = _userManager.PasswordHasher.HashPassword(user, model.NewPassword);

            _userRepository.Update(user);
            _token.Delete(token);
            await _token.SaveChangesAsync();

            await _userRepository.SaveChangesAsync();

            return new ApiResponse<object>
            {
                Message = ResponseMessages.PasswordResetSuccessfully,
                Data = null
            };
        }

        public async Task<ApiResponse<GetConifrmedTokenUserDto>> ConfirmToken(VerifyTokenDTO model)
        {
            var token = await _token.FirstOrDefaultAsync(x => x.Value == model.Token, true);
            if (token == null)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.InvalidExpiredToken);

            if (DateTime.Now >= token.ExpiresAt)
            {
                _token.Delete(token);
                await _token.SaveChangesAsync();

                throw new RestException(HttpStatusCode.BadRequest, ResponseMessages.TokenExpired);
            }

            var user = await _userRepository.FirstOrDefaultAsync(x => x.Id == token.UserId, false);
            if (user == null)
                throw new RestException(HttpStatusCode.BadRequest, ResponseMessages.InvalidToken);

            if (token.TokenType == ETokenType.RegisterUser.ToString() &&
                (token.ExpiresAt - DateTime.Now) <= TimeSpan.FromMinutes(30))
            {
                token.ExpiresAt = token.ExpiresAt.AddMinutes(30);
                _token.Update(token);
                await _token.SaveChangesAsync();
                await _userRepository.SaveChangesAsync();
            }

            return new ApiResponse<GetConifrmedTokenUserDto>
            {
                Message = ResponseMessages.TokenConfirmedSuccessfully,
                Data = new GetConifrmedTokenUserDto
                {
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName
                }
            };
        }

        #region Private methods to manage Authentication 
        private TokenReturnHelper Authenticate(User user, IList<string> roles)
        {
            var roleClaims = new List<Claim>();
            var claims = new List<Claim>
            {
                new Claim(ClaimTypeHelper.Email, user.Email),
                new Claim(ClaimTypeHelper.UserId, user.Id.ToString())
            };

            foreach (var role in roles)
            {
                roleClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            claims.AddRange(roleClaims);

            var jwtSettings = _configuration.GetSection("JwtSettings");
            var jwtUserSecret = jwtSettings.GetSection("Secret").Value;
            var tokenLifeSpan = jwtSettings.GetSection("TokenLifeSpan").Value;
            var tokenExpireIn = string.IsNullOrEmpty(tokenLifeSpan) ? int.Parse(tokenLifeSpan) : 7;
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(jwtUserSecret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(tokenExpireIn),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var jwt = tokenHandler.WriteToken(token);

            return new TokenReturnHelper
            {
                ExpiresIn = tokenDescriptor.Expires,
                AccessToken = jwt
            };
        }
        private string GenerateRefreshToken(Guid userId)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var jwtUserSecret = jwtSettings.GetSection("Secret").Value;
            var tokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(jwtUserSecret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypeHelper.UserId, userId.ToString())
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var jwt = tokenHandler.WriteToken(token);

            return jwt;
        }
        private bool ValidateRefreshToken(string refreshToken)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var jwtUserSecret = jwtSettings.GetSection("Secret").Value;

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtUserSecret)),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(refreshToken, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                StringComparison.InvariantCultureIgnoreCase))
            {
                return false;
            }

            var expiryAt = jwtSecurityToken.ValidTo;
            if (DateTime.UtcNow > expiryAt)
                return false;
            return true;
        }
        private Guid GetUserIdFromAccessToken(string accessToken)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var jwtUserSecret = jwtSettings.GetSection("Secret").Value;

            var tokenValidationParamters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtUserSecret)),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParamters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                                                    StringComparison.InvariantCultureIgnoreCase))
            {
                throw new RestException(HttpStatusCode.BadRequest, ResponseMessages.InvalidToken);
            }

            var userId = principal.FindFirst(ClaimTypeHelper.UserId)?.Value;

            if (userId == null)
                throw new RestException(HttpStatusCode.BadRequest, $"{ResponseMessages.MissingClaim} {ClaimTypeHelper.UserId}");

            return Guid.Parse(userId);
        }

        public async Task<ApiResponse<object>> SendToken(SendTokenInputDto input)
        {
            Token token = new();
            var initialMember = await GetAlreadyUserByEmail(input.Email.Trim().ToLower());

            var otp = CustomToken.GenerateOtp();
            if (input.TokenType.Equals(ETokenType.RegisterUser.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                var registertokenEntity = await _token.FirstOrDefaultAsync(x => x.TokenType == ETokenType.RegisterUser.ToString() && x.UserId == initialMember.Id, false);
                if (registertokenEntity != null)
                {
                    _token.Delete(registertokenEntity);

                    await _token.SaveChangesAsync();
                }

                token = new Token
                {
                    UserId = initialMember.Id,
                    Value = otp,
                    TokenType = ETokenType.RegisterUser.ToString()
                };
            }

            if (input.TokenType.Equals(ETokenType.ForgetPassword.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                var user = await GetAlreadyUserByEmail(input.Email.ToLower().Trim());
                var forgotPasswordtokenEntity = await _token.FirstOrDefaultAsync(x => x.TokenType == ETokenType.ForgetPassword.ToString() && x.UserId == user.Id, false);
                if (forgotPasswordtokenEntity != null)
                {
                    _token.Delete(forgotPasswordtokenEntity);
                    await _token.SaveChangesAsync();
                }

                token = new Token
                {
                    UserId = user.Id,
                    Value = otp,
                    TokenType = ETokenType.ForgetPassword.ToString()
                };
            }

            //var message = _mailerService.GetOtpEmailTemplate(otp);
            //string subject = "MIPAD OTP";

            //await _emailClient.SendEmailAsync(input.Email, message, subject);

            await _token.CreateAsync(token);
            await _token.SaveChangesAsync();

            return new ApiResponse<object>
            {
                Message = ResponseMessages.OtpSentSuccessfully,
                Data = null
            };
        }

        private async Task<User> GetAlreadyUserByEmail(string email)
        {
            var initialMember = await _userRepository.FirstOrDefaultAsync(x => x.Email.Trim().ToLower() == email.ToLower(), false);
            if (initialMember is null)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.InitialMemberNotFound);
            return initialMember;
        }

        private async Task<User> GetUserByEmail(string email)
        {
            var user = await _userRepository.FirstOrDefaultAsync(x => x.Email == email, false);
            if (user is null)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.UserNotFound);
            return user;
        }

        public async Task<ApiResponse<ReferenceTokenResponseDto>> VerifyOtp(VerifyTokenDTO model)
        {
            var tokenEntity = await _token.FirstOrDefaultAsync(x => x.Value == model.Token, false);
            if (tokenEntity == null)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.InvalidExpiredToken);
            var expirytime = _configuration.GetSection("OTP:ExpiryTime");
            if ((DateTime.Now - tokenEntity.ExpiresAt).TotalHours > Convert.ToInt32(expirytime.Value))
            {
                _token.Delete(tokenEntity);
                await _token.SaveChangesAsync();

                throw new RestException(HttpStatusCode.BadRequest, ResponseMessages.TokenExpired);
            }

            Token token = new();
            if (tokenEntity.TokenType.Equals(ETokenType.RegisterUser.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                var initialMember = await _userRepository.FirstOrDefaultAsync(x => x.Id == tokenEntity.UserId, false);
                if (initialMember is null)
                    throw new RestException(HttpStatusCode.BadRequest, ResponseMessages.InvalidToken);

                token = new Token
                {
                    Id = Guid.NewGuid(),
                    UserId = initialMember.Id,
                    Value = CustomToken.GenerateRandomString(25),
                    TokenType = ETokenType.ReferenceToken.ToString()
                };

            }

            if (tokenEntity.TokenType.Equals(ETokenType.ForgetPassword.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                var user = await _userRepository.FirstOrDefaultAsync(x => x.Id == tokenEntity.UserId, false);
                if (user is null)
                    throw new RestException(HttpStatusCode.BadRequest, ResponseMessages.InvalidToken);

                token = new Token
                {
                    Id = Guid.NewGuid(),
                    UserId = user.Id,
                    Value = CustomToken.GenerateRandomString(25),
                    TokenType = ETokenType.ReferenceToken.ToString()
                };
            }

            _token.Delete(tokenEntity);
            await _token.CreateAsync(token);
            await _token.SaveChangesAsync();
            await _userRepository.SaveChangesAsync();

            return new ApiResponse<ReferenceTokenResponseDto>
            {
                Message = ResponseMessages.TokenConfirmedSuccessfully,
                Data = new ReferenceTokenResponseDto
                {
                    ReferenceToken = token?.Value
                }
            };
        }

        public async Task<ApiResponse<GetInitialMemberTokenResponseDto>> GetUserByReferenceToken(ReferenceTokenInputDto model)
        {
            var referenceToken = await _token.FirstOrDefaultAsync(x => x.Value == model.ReferenceToken, false);
            if (referenceToken == null)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.InvalidExpiredToken);

            if (DateTime.Now >= referenceToken.ExpiresAt)
            {
                _token.Delete(referenceToken);
                await _token.SaveChangesAsync();

                throw new RestException(HttpStatusCode.BadRequest, ResponseMessages.TokenExpired);
            }

            var initialMember = await _userRepository.FirstOrDefaultAsync(x => x.Id == referenceToken.UserId, false);
            if (initialMember is null)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.InvalidToken);

            return new ApiResponse<GetInitialMemberTokenResponseDto>
            {
                Message = ResponseMessages.ReferenceTokenConfirmedSuccessfully,
                Data = _mapper.Map<GetInitialMemberTokenResponseDto>(initialMember)
            };
        }

        public async Task<ApiResponse<object>> ChangePassword(ChangePasswordDto model)
        {
            var userMember = await _userRepository.FindByCondition(x => x.Id == model.UserId, true).FirstOrDefaultAsync();
            if (userMember is null)
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.UserNotFound);

            var isPasswordCorrect = await _userManager.CheckPasswordAsync(userMember, model.OldPassword);
            if (!isPasswordCorrect)
                throw new RestException(HttpStatusCode.BadRequest, ResponseMessages.WrongPassword);

            var result = await _userManager.ChangePasswordAsync(userMember, model.OldPassword, model.NewPassword);
            if (!result.Succeeded)
                throw new RestException(HttpStatusCode.BadRequest, result.Errors.FirstOrDefault().Description);

            return new ApiResponse<object>
            {
                Message = ResponseMessages.PasswordChangedSuccessfully,
                Data = null
            };
        }

        public async Task<ApiResponse<UserMemberResponseDto>> GetUserMemberById(Guid id)
        {
            var userId = _webHelper.User().UserId;
            var member = await _userRepository.FindByCondition(x => x.Id == id, false).FirstOrDefaultAsync();
            if (member is null)
            {
                throw new RestException(HttpStatusCode.NotFound, ResponseMessages.UserNotFound);
            }
            return new ApiResponse<UserMemberResponseDto>
            {
                Message = ResponseMessages.RetrievalSuccessResponse,
                Data = _mapper.Map<UserMemberResponseDto>(member)
            };
        }
        #endregion
    }
}
