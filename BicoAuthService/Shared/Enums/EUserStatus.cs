using System.ComponentModel;

namespace BicoAuthService.Shared.Enums
{
    public enum EUserStatus
    {
        [Description("Active")]
        Active = 1,
        [Description("Pending")]
        Pending = 2,
        [Description("Disabled")]
        Disabled = 3,
    }

    public enum ETokenType
    {
        [Description("RegisterUser")]
        RegisterUser,
        [Description("ReferenceToken")]
        ReferenceToken,
        [Description("ForgetPassword")]
        ForgetPassword
    }

    public enum ERole
    {
        Regular,
        Manager,
        Admin
    }
}
