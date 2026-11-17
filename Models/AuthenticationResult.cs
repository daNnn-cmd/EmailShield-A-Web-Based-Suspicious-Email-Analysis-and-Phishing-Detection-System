using System;
using System.Collections.Generic;

namespace EmailShield.Models;

public partial class AuthenticationResult
{
    public int AuthenticationId { get; set; }

    public int EmailId { get; set; }

    public string? Spfresult { get; set; }

    public string? Dkimresult { get; set; }

    public string? Dmarcresult { get; set; }

    public string? AuthenticationHeader { get; set; }

    public string? VerificationMethod { get; set; }

    public DateTime CheckedAt { get; set; }

    public virtual EmailSample Email { get; set; } = null!;
}
