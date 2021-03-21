using System;
using System.Collections.Generic;
using System.Text;

using Prism.Mvvm;
using Prism.Commands;
using Reactive.Bindings;
using Reactive.Bindings.Extensions;

using System.Threading.Tasks;

namespace EncryptServerTest
{
    public class MainWindowVM : BindableBase
    {
        public ReactiveProperty<string> ClientText { get; set; }
        public ReactiveProperty<string> ServerText { get; set; }
        public ReactiveProperty<string> EncriptedClientText { get; set; }
        public ReactiveProperty<string> EncriptedServerText { get; set; }

        public DelegateCommand SendCommand { get; set; }

        private MainWindowM model;

        public MainWindowVM()
        {
            model = new MainWindowM();

            ClientText = model.ToReactivePropertyAsSynchronized(x => x.Client.Text);
            ServerText = model.ToReactivePropertyAsSynchronized(x => x.Server.Text);
            EncriptedClientText = model.ToReactivePropertyAsSynchronized(x => x.Client.Encrypted);
            EncriptedServerText = model.ToReactivePropertyAsSynchronized(x => x.Server.Encrypted);

            SendCommand = model.Client.SendCommand;
        }
    }
}
