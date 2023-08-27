using System.Security.Cryptography;
using System.Text;
using LiteNetLib.Utils;

const string PasswordCheckValue = "hi";

Console.WriteLine("Hello, World!");

string currentPath = Directory.GetCurrentDirectory();
string plaintextPath = $@"{currentPath}\plaintext";
string ciphertextPath = $@"{currentPath}\ciphertext";
string initializedPath = $@"{currentPath}\initialized";

Directory.CreateDirectory(ciphertextPath);

string? password = null;

ReenterPassword:

if (!File.Exists(initializedPath))
{
    password = CreatePassword();
    byte[] encryptedData = EncryptWithPassword(password, Encoding.UTF8.GetBytes(PasswordCheckValue));
    File.WriteAllBytes(initializedPath, encryptedData);
}

if (password == null)
{
    Console.Write("Enter your password: ");
    password = Console.ReadLine()!;
}

// Ensure password is correct
{
    byte[] encryptedData = File.ReadAllBytes(initializedPath);

    try
    {
        byte[] data = DecryptWithPassword(password, encryptedData);
        string passwordCheckValue = Encoding.UTF8.GetString(data);
        if (passwordCheckValue != PasswordCheckValue)
        {
            throw new Exception();
        }
    }
    catch
    {
        Console.WriteLine("Password is incorrect!");
        password = null;
        goto ReenterPassword;
    }
}

Console.Clear();

Console.WriteLine($"Warning: Plaintext files cannot not be larger than {ushort.MaxValue} bytes!");
Console.WriteLine($"Warning: Plaintext files must be in a flat directory!");

long? versionToLoad = null;
{
    var ciphertextFiles = Directory.GetFiles(ciphertextPath);
    foreach (var ciphertextFile in ciphertextFiles)
    {
        var split = ciphertextFile.Split('\\');
        long version = long.Parse(split[^1]);

        if (versionToLoad == null)
        {
            versionToLoad = version;
        }
        else
        {
            if (version > versionToLoad)
            {
                versionToLoad = version;
            }
        }
    }
}

if (Directory.Exists(plaintextPath))
{
    bool shouldDelete;
    while (true)
    {
        Console.WriteLine("The plaintext directory exists, are you okay with deleting it? (\"yes\" or \"no\")");
        string yesOrNo = Console.ReadLine()!;
        yesOrNo = yesOrNo.Trim();
        if (yesOrNo == "yes")
        {
            shouldDelete = true;
            break;
        }
        else if (yesOrNo == "no")
        {
            shouldDelete = false;
            break;
        }
    }

    if (shouldDelete)
    {
        Directory.Delete(plaintextPath, true);
    }
    else
    {
        goto Save;
    }
}

Directory.CreateDirectory(plaintextPath);

if (versionToLoad != null)
{
    byte[] encryptedData = File.ReadAllBytes($@"{ciphertextPath}\{versionToLoad}");
    byte[] data = DecryptWithPassword(password, encryptedData);
    NetDataReader reader = new(data);

    int fileCount = reader.GetInt();
    for (int i = 0; i < fileCount; i++)
    {
        string fileName = reader.GetString();
        string fileText = reader.GetString();
        File.WriteAllText($@"{plaintextPath}\{fileName}", fileText);
    }

    Console.WriteLine($"Loaded version {versionToLoad}.");
}
else
{
    Console.WriteLine("No ciphertext was found, nothing was loaded into plaintext.");
}

Console.WriteLine("Enter to save and exit.");
Console.ReadLine();

Save:

NetDataWriter writer = new();

// Load plaintext data into memory
{
    List<(string fileName, string fileText)> data = new();
    var plaintextFiles = Directory.GetFiles(plaintextPath);
    foreach (var plaintextFile in plaintextFiles)
    {
        var split = plaintextFile.Split('\\');
        string fileName = split[^1];
        string fileText = File.ReadAllText(plaintextFile);
        data.Add((fileName, fileText));
    }

    {
        int fileCount = data.Count;
        writer.Put(fileCount);
        foreach ((string fileName, string fileText) in data)
        {
            writer.Put(fileName);
            writer.Put(fileText);
        }
    }
}

// Encrypt and save the data
{
    long versionToSave = versionToLoad == null ? 0 : versionToLoad.Value + 1;
    byte[] encryptedData = EncryptWithPassword(password, writer.CopyData());
    File.WriteAllBytes($@"{ciphertextPath}/{versionToSave}", encryptedData);
}

Directory.Delete(plaintextPath, true);

static string CreatePassword()
{
    string password;

    while (true)
    {
        Console.Write("Create a password: ");
        string a = Console.ReadLine()!;

        Console.Write("Confirm your password: ");
        string b = Console.ReadLine()!;

        if (a == b)
        {
            password = a;
            break;
        }
    }

    return password;
}

static byte[] EncryptWithPassword(string password, byte[] data)
{
    byte[] encryptedData;

    using (Aes aes = Aes.Create())
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] aesKey = SHA256.HashData(passwordBytes);
        byte[] aesIV = MD5.HashData(passwordBytes);

        aes.Key = aesKey;
        aes.IV = aesIV;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        ICryptoTransform encryptor = aes.CreateEncryptor(aesKey, aesIV);

        using MemoryStream msEncrypt = new();
        using CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write);
        using (BinaryWriter bwEncrypt = new(csEncrypt))
        {
            bwEncrypt.Write(data);
        }

        encryptedData = msEncrypt.ToArray();
    }

    return encryptedData;
}

static byte[] DecryptWithPassword(string password, byte[] encryptedData)
{
    byte[] data;

    using Aes aes = Aes.Create();
    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
    byte[] aesKey = SHA256.HashData(passwordBytes);
    byte[] aesIV = MD5.HashData(passwordBytes);

    aes.Key = aesKey;
    aes.IV = aesIV;
    aes.Mode = CipherMode.CBC;
    aes.Padding = PaddingMode.PKCS7;

    ICryptoTransform decryptor = aes.CreateDecryptor(aesKey, aesIV);

    using (MemoryStream msDecrypt = new(encryptedData))
    {
        using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
        using BinaryReader brDecrypt = new(csDecrypt);
        using MemoryStream ms = new();
        brDecrypt.BaseStream.CopyTo(ms);
        data = ms.ToArray();
    }

    return data;
}