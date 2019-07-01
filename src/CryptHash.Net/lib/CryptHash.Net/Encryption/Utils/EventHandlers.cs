/*
 *      Alessandro Cagliostro, 2019
 *      
 *      https://github.com/alecgn
 */

namespace CryptHash.Net.Encryption.Utils.EventHandlers
{
    public delegate void OnEncryptionMessageHandler(string message);

    public delegate void OnEncryptionProgressHandler(int percentageDone, string message);
}
