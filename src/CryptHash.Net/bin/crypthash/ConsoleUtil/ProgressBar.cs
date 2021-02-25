﻿/*
 *      Thanks to Daniel Wolf for this great console progress bar
 *      A little modification was made by me to fit the progress bar to the console width
 * 
 *      GitHub profile: https://github.com/DanielSWolf
 *      Source code available in: https://gist.github.com/DanielSWolf/0ab6a96899cc5377bf54
 * 
 *      Console progress bar.Code is under the MIT License: http://opensource.org/licenses/MIT
*/

using System;
using System.Text;
using System.Threading;

namespace CryptHash.Net.CLI.ConsoleUtil
{
    /// <summary>
    /// An ASCII progress bar
    /// </summary>
    public class ProgressBar : IDisposable, IProgress<double>
    {
        //private const int blockCount = 10;
        private readonly int blockCount;
        private readonly TimeSpan animationInterval = TimeSpan.FromSeconds(1.0 / 8);
        private const string animation = @"|/-\";

        private readonly Timer timer;

        private double currentProgress = 0;
        private string currentText = string.Empty;
        private bool disposed = false;
        private int animationIndex = 0;

        public ProgressBar(int blockCount = 0)
        {
            this.blockCount = (blockCount == 0 ? (Console.WindowWidth - 10) : blockCount);
            timer = new Timer(TimerHandler);
            //timer = new Timer(TimerHandler, new AutoResetEvent(false), TimeSpan.FromSeconds(1.0 / 8), TimeSpan.FromSeconds(1.0 / 8));

            // A progress bar is only for temporary display in a console window.
            // If the console output is redirected to a file, draw nothing.
            // Otherwise, we'll end up with a lot of garbage in the target file.
            if (!Console.IsOutputRedirected)
            {
                ResetTimer();
            }
        }

        public void Report(double value)
        {
            // Make sure value is in [0..1] range
            value = Math.Max(0, Math.Min(1, value));
            Interlocked.Exchange(ref currentProgress, value);
        }

        public void WriteLine(string text)
        {
            lock (timer)
            {
                UpdateText(string.Empty);
                Console.WriteLine(text);
                UpdateText(currentText);
            }
        }

        private void TimerHandler(object state)
        {
            lock (timer)
            {
                if (disposed)
                {
                    return;
                }

                var progressBlockCount = (int)(currentProgress * blockCount);
                var percent = (int)(currentProgress * 100);
                var text = string.Format("[{0}{1}] {2,3}% {3}",
                    new string('#', progressBlockCount), new string('-', blockCount - progressBlockCount),
                    percent,
                    animation[animationIndex++ % animation.Length]);
                UpdateText(text);

                ResetTimer();
            }
        }

        private void UpdateText(string text)
        {
            // Get length of common portion
            var commonPrefixLength = 0;
            var commonLength = Math.Min(currentText.Length, text.Length);

            while (commonPrefixLength < commonLength && text[commonPrefixLength] == currentText[commonPrefixLength])
            {
                commonPrefixLength++;
            }

            // Backtrack to the first differing character
            var outputBuilder = new StringBuilder();
            outputBuilder.Append('\b', currentText.Length - commonPrefixLength);

            // Output new suffix
            outputBuilder.Append(text.Substring(commonPrefixLength));

            // If the new text is shorter than the old one: delete overlapping characters
            var overlapCount = currentText.Length - text.Length;

            if (overlapCount > 0)
            {
                outputBuilder.Append(' ', overlapCount);
                outputBuilder.Append('\b', overlapCount);
            }

            Console.Write(outputBuilder);
            currentText = text;
        }

        private void ResetTimer()
        {
            timer.Change(animationInterval, TimeSpan.FromMilliseconds(-1));
        }

        public void Dispose()
        {
            lock (timer)
            {
                disposed = true;
                UpdateText(string.Empty);
                timer.Dispose();
            }
        }
    }
}
