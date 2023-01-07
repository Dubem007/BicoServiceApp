namespace BicoAuthService.Entities.DataTransferObjects
{
    public class CreateUserInputDTO
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Role { get; set; }
        public string Category { get; set; }
    }
    public class CreateUserResponse
    {
        public Guid Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
    }
    public class UserLoginResponse
    {
        public string AccessToken { get; set; }
        public DateTime? ExpiresIn { get; set; }
        public string RefreshToken { get; set; }
    }

    public class UserByIdResponse
    {
        public Guid Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Status { get; set; }
        public bool IsActive { get; set; }
        public bool Verified { get; set; }
    }
    public class RefreshTokenResponse
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public DateTime? ExpiresIn { get; set; }
    }
    public class UpdateAdminResponse
    {
        public Guid Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
    }

    public class TokenReturnHelper
    {
        public string AccessToken { get; set; }
        public DateTime? ExpiresIn { get; set; }
    }

    public class GetConifrmedTokenUserDto
    {
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }

    public class UserLoginDTO
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class ChangePasswordDto
    {
        public Guid UserId { get; set; }
        public string OldPassword { get; set; }
        public string NewPassword { get; set; }
    }

    public class RefreshTokenDTO
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }

    public class SetPasswordDTO
    {
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public IFormFile ProfilePicture { get; set; }
        public string Password { get; set; }
        public string Token { get; set; }
    }

    public class ResetPasswordDto
    {
        public string Email { get; set; }
    }

    public class SendTokenInputDto
    {
        public string Email { get; set; }
        public string TokenType { get; set; }
    }

    public class GetInitialMemberTokenResponseDto
    {
        public Guid Id { get; set; }
        public string Email { get; set; }
    }

    public record ReferenceTokenResponseDto
    {
        public string ReferenceToken { get; set; }
    }

    public record ReferenceTokenInputDto
    {
        public string ReferenceToken { get; set; }
    }

    public class VerifyTokenDTO
    {
        public string Token { get; set; }
        public string TokenType { get; set; }
    }

    public class GetSetPasswordDto
    {
        public Guid UserId { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string ImageUrl { get; set; }
    }

    public class ResetPasswordDTO
    {
        public string ReferenceToken { get; set; }
        public string NewPassword { get; set; }
    }

    public class SearchUserMemberDto
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string ImageUrl { get; set; }
        public string ProfessionalField { get; set; }
        public string RecognitionYear { get; set; }
        public string Location { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
    public class UserDataDto
    {

        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string ImageUrl { get; set; }
    }

    public record UserMemberCreationInputDto
    {
        //public string ReferenceToken { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string PrefferedName { get; set; }
        public string Email { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string ProfessionalField { get; set; }
        public IFormFile ProfileImage { get; set; }
        public string Location { get; set; }
        public string Bio { get; set; }
        public string Password { get; set; }
        public string Country { get; set; }

    }

    public record UserMemberUpdateInputDto
    {
        public Guid UserMemberId { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string PrefferedName { get; set; }
        public string Email { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string ProfessionalField { get; set; }
        public IFormFile ProfileImage { get; set; }
        public string Location { get; set; }
        public string Bio { get; set; }
        public string Country { get; set; }
    }

    public class UserMemberResponseDto
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string PrefferedName { get; set; }
        public string Email { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string ProfessionalField { get; set; }
        public string ProfileImage { get; set; }
        public string Location { get; set; }
        public string Bio { get; set; }
        public string Country { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}
