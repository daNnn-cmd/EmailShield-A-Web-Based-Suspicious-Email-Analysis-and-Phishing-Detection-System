using System;
using System.Collections.Generic;

namespace EmailShield.Models;

public partial class EmailHeader
{
    public int HeaderId { get; set; }

    public int EmailId { get; set; }

    public string HeaderName { get; set; } = null!;

    public string? HeaderValue { get; set; }

    public virtual EmailSample Email { get; set; } = null!;
}
