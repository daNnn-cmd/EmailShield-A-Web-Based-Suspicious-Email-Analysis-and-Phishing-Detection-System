using System;
using System.Collections.Generic;

namespace EmailShield.Models;

public partial class AttachmentMetadatum
{
    public int AttachmentId { get; set; }

    public int EmailId { get; set; }

    public string FileName { get; set; } = null!;

    public string? FileExtension { get; set; }

    public string? MimeType { get; set; }

    public long? FileSize { get; set; }

    public bool IsSuspicious { get; set; }

    public string? DetectionReason { get; set; }

    public DateTime InspectedAt { get; set; }

    public virtual EmailSample Email { get; set; } = null!;
}
