using Autofac.Core;
using BicoAuthService.Entities.DataTransferObjects;
using BicoAuthService.Helpers;
using BicoAuthService.Interface;
using BicoAuthService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace BicoAuthService.Controllers
{
   
    [Authorize]
    [ApiController]
    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthentication _authentication;
        public AuthController(IAuthentication authentication)
        {
            _authentication = authentication;
        }

        /// <summary>
        /// Endpoint to create a User
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("Register-User")]
        [ProducesResponseType(typeof(UserMemberCreationInputDto), (int)HttpStatusCode.Created)]
        public async Task<IActionResult> RegisterUser([FromForm] UserMemberCreationInputDto input)
        {
            var response = await _authentication.CreateUserMember(input);
            return CreatedAtAction(nameof(GetUserMember), new { id = response.Data.Id }, response);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        //[AllowAnonymous]
        [HttpGet("{id}")]
        [ProducesResponseType(typeof(UserMemberCreationInputDto), (int)HttpStatusCode.Created)]
        [ProducesResponseType((int)HttpStatusCode.Unauthorized)]
        public async Task<IActionResult> GetUserMember(Guid id)
        {
            var response = await _authentication.GetUserMemberById(id);

            return Ok(response);
        }
        /// <summary>
        /// Endpoint to update a User
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPut("Update-User")]
        [ProducesResponseType(typeof(UserMemberUpdateInputDto), (int)HttpStatusCode.Created)]
        public async Task<IActionResult> UpdateUser([FromForm] UserMemberUpdateInputDto input)
        {
            var response = await _authentication.UpdateUserMember(input);
            return Ok(response);
        }

        // <summary>
        /// Endpoint to login a user
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("login")]
        [ProducesResponseType(typeof(ApiResponse<UserLoginResponse>), 200)]
        public async Task<IActionResult> LoginUser(UserLoginDTO model)
        {
            var response = await _authentication.Login(model);

            return Ok(response);
        }

        /// <summary>
        /// Endpoint to generate a new access and refresh token
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("refresh-token")]
        [ProducesResponseType(typeof(ApiResponse<RefreshTokenResponse>), 200)]
        public async Task<IActionResult> RefreshToken(RefreshTokenDTO model)
        {
            var response = await _authentication.GetRefreshToken(model);

            return Ok(response);
        }

        /// <summary>
        /// Endpoint to initializes password reset
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("reset-password")]
        [ProducesResponseType(typeof(ApiResponse<object>), 200)]
        public async Task<IActionResult> ForgotPassword(ResetPasswordDTO model)
        {
            var response = await _authentication.ResetPassword(model);

            return Ok(response);
        }

        /// <summary>
        /// Endpoint to change password
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("change-password")]
        [ProducesResponseType(typeof(ApiResponse<object>), 200)]
        public async Task<IActionResult> ChangePassword(ChangePasswordDto model)
        {
            var response = await _authentication.ChangePassword(model);

            return Ok(response);
        }

        /// <summary>
        /// Endpoint to verify token
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("verify-token")]
        [ProducesResponseType(typeof(ApiResponse<GetConifrmedTokenUserDto>), 200)]
        public async Task<IActionResult> VerifyToken(VerifyTokenDTO model)
        {
            var response = await _authentication.ConfirmToken(model);

            return Ok(response);
        }

        /// <summary>
        /// Endpoint to set password
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("set-password")]
        [ProducesResponseType(typeof(ApiResponse<GetSetPasswordDto>), 200)]
        public async Task<IActionResult> SetPassword([FromForm] SetPasswordDTO model)
        {
            var response = await _authentication.SetPassword(model);

            return Ok(response);
        }

        /// <summary>
        /// Endpoint to send otp
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("send-otp")]
        [ProducesResponseType(typeof(ApiResponse<object>), 200)]
        public async Task<IActionResult> SendToken([FromBody] SendTokenInputDto input)
        {
            var response = await _authentication.SendToken(input);

            return Ok(response);
        }

        /// <summary>
        /// Endpoint to confirm otp
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost("confirm-otp")]
        [ProducesResponseType(typeof(ApiResponse<ReferenceTokenResponseDto>), 200)]
        public async Task<IActionResult> VerifyOtp([FromBody] VerifyTokenDTO model)
        {
            var response = await _authentication.VerifyOtp(model);

            return Ok(response);
        }
    }
}
