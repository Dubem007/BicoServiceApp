using BicoAuthService.Entities;

namespace BicoAuthService.Helpers
{
    public class CustomToken
    {
        private static readonly Random random = new();
        public static string GenerateToken()
        {
            return Convert.ToBase64String(Guid.NewGuid().ToByteArray());
        }
        public static string GenerateOtp()
        {
            Random rnd = new();
            var randomNumber = (rnd.Next(100000, 999999)).ToString();
            return randomNumber;
        }
        public static bool IsTokenValid(Token token)
        {
            var expiry = token.ExpiresAt;
            if (DateTime.UtcNow > expiry)
                return false;

            return true;
        }

        public static string GenerateRandomString(int length)
        {
            Int32 unixTimestamp = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            string chars = unixTimestamp.ToString() + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";

            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}
