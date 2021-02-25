/*
 *      Alessandro Cagliostro, 2021
 *      
 *      https://github.com/alecgn
 */

namespace CryptHash.Net.Util.EventHandlers
{
    public delegate void OnEncryptionMessageHandler(string message);

    public delegate void OnDecryptionMessageHandler(string message);

    public delegate void OnEncryptionProgressHandler(int percentageDone, string message);

    public delegate void OnDecryptionProgressHandler(int percentageDone, string message);

    public delegate void OnHashProgressHandler(int percentageDone, string message);
}
