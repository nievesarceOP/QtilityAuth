namespace QtilityAuth.Shared
{
    public class LoginResponse
    {
        public LoginResponse(bool succeeded, string jwt)
        {
            this.Succeeded = succeeded;
            this.JWT = jwt;
        }

        public static LoginResponse Failed { get; set; } = new LoginResponse(false, string.Empty);
        public bool Succeeded { get; set; }
        public string JWT { get; set; }
    }
}
