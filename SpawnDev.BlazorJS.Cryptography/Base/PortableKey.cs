namespace SpawnDev.BlazorJS.Cryptography
{
    /// <summary>
    /// PortableKey abstract class
    /// </summary>
    public abstract class PortableKey : IDisposable, IAsyncDisposable
    {
        /// <summary>
        /// Key algorithm
        /// </summary>
        public abstract string AlgorithmName { get; }
        /// <summary>
        /// Returns true if the private key can be extracted
        /// </summary>
        public virtual bool Extractable { get; protected set; } = true;
        /// <summary>
        /// Key usages
        /// </summary>
        public virtual string[] Usages { get; protected set; } = Array.Empty<string>();
        /// <summary>
        /// Returns true if this instance has been disposed
        /// </summary>
        public bool IsDisposed { get; protected set; }
        /// <summary>
        /// Dispose instance resources
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing) { }
        /// <summary>
        /// Dispose instance resources
        /// </summary>
        public void Dispose()
        {
            if (IsDisposed) return;
            IsDisposed = true;
            GC.SuppressFinalize(this);
            Dispose(false);
        }
        /// <summary>
        /// Dispose instance resources
        /// </summary>
        public virtual ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }
        /// <summary>
        /// Instance finalizer
        /// </summary>
        ~PortableKey()
        {
            Dispose(false);
        }
    }
}
