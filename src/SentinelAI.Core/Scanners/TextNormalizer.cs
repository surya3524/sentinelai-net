using System.Text;

namespace SentinelAI.Scanners;

/// <summary>
/// Produces a canonical form of text so rules match what a model actually "reads":
/// Unicode NFKC folding, removal of invisible formatting characters, and decoding of
/// Unicode tag characters (U+E0000 block) that render as nothing but are readable by models.
/// </summary>
public static class TextNormalizer
{
    public sealed record Result(string Text, int InvisibleCharCount, string? DecodedTagText);

    public static Result Normalize(string input)
    {
        var sb = new StringBuilder(input.Length);
        var tags = new StringBuilder();
        var invisible = 0;

        for (var i = 0; i < input.Length; i++)
        {
            var c = input[i];

            if (char.IsHighSurrogate(c) && i + 1 < input.Length && char.IsLowSurrogate(input[i + 1]))
            {
                var cp = char.ConvertToUtf32(c, input[i + 1]);
                i++;
                if (cp is >= 0xE0000 and <= 0xE007F)
                {
                    invisible++;
                    if (cp is >= 0xE0020 and <= 0xE007E) tags.Append((char)(cp - 0xE0000));
                    continue;
                }
                sb.Append(char.ConvertFromUtf32(cp));
                continue;
            }

            if (IsInvisible(c))
            {
                invisible++;
                continue;
            }
            sb.Append(c);
        }

        var tagText = tags.Length > 0 ? tags.ToString() : null;
        var text = sb.ToString().Normalize(NormalizationForm.FormKC);
        if (tagText is not null) text += "\n" + tagText;
        return new Result(text, invisible, tagText);
    }

    private static bool IsInvisible(char c) =>
        c is '​' or '‌' or '‍' or '‎' or '‏'
          or '⁠' or '⁡' or '⁢' or '⁣' or '⁤'
          or '﻿' or '­' or '᠎'
        || (c >= '‪' && c <= '‮')
        || (c >= '⁦' && c <= '⁩');
}
