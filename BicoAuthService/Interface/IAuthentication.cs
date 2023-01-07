using BicoAuthService.Entities.DataTransferObjects;
using BicoAuthService.Helpers;

namespace BicoAuthService.Interface
{
    public interface IAuthentication : IAutoDependencyService
    {
        Task<ApiResponse<UserLoginResponse>> Login(UserLoginDTO model);
        Task<ApiResponse<RefreshTokenResponse>> GetRefreshToken(RefreshTokenDTO model);
        Task<ApiResponse<GetSetPasswordDto>> SetPassword(SetPasswordDTO model);
        Task<ApiResponse<object>> ResetPassword(ResetPasswordDTO model);
        Task<ApiResponse<GetConifrmedTokenUserDto>> ConfirmToken(VerifyTokenDTO model);
        Task<ApiResponse<object>> SendToken(SendTokenInputDto model);
        Task<ApiResponse<ReferenceTokenResponseDto>> VerifyOtp(VerifyTokenDTO model);
        Task<ApiResponse<GetInitialMemberTokenResponseDto>> GetUserByReferenceToken(ReferenceTokenInputDto model);
        //Task<ApiResponse<object>> ChangePassword(ChangePasswordDto model);
        Task<ApiResponse<UserMemberResponseDto>> CreateUserMember(UserMemberCreationInputDto input);
        Task<ApiResponse<UserMemberResponseDto>> UpdateUserMember(UserMemberUpdateInputDto input);
        Task<ApiResponse<UserMemberResponseDto>> GetUserMemberById(Guid id);
        Task<ApiResponse<object>> ChangePassword(ChangePasswordDto model);
    }
    
}
