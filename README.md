# Documentação
Esta é a documentação referente à aplicação anti-ransomware produzida pelo grupo EttoreSec. Aqui você encontrará todo o passo a passo para o download, compilação, instalação e execução de toda a nossa aplicação, além de dependências requeridas.

## Aplicações requeridas para a compilação, instalação e execução da aplicação
 - Visual Studio, com a carga de trabalho "Desenvolvimento para desktop em C++";
 - Bibliotecas com mitigação de Spectre do visual studio (componentes individuais do Visual Studio);
 - Windows WDK;
 - Windows SDK.

*Obs: todas as versões devem ser comparadas com a versão do windows que está sendo usada, e por isso deve-se atentar cuidadosamente ao se instalar qualquer um dos softwares acimas, que devem possuir versões compatíveis entre si e com a versão do Windows utilizada. Os seguintes links apresentam todas as versões compatíveis com o sistema operacional e entre si:
 - https://learn.microsoft.com/pt-br/windows-hardware/drivers/other-wdk-downloads
 - https://developer.microsoft.com/pt-br/windows/downloads/windows-sdk/

## Passo a passo para executar o software
No geral, tudo que se deve fazer é baixar o repositório, compilar cada uma das aplicações, colocar o windows em modo de teste, habilitar a instalação de drivers não assinados, instalar o certificado do mini filter e, por fim, executar cada um dos softwares.

### Fazendo o download do software
Por meio do software `git`, é possível fazer o download por meio do seguinte comando:
```shell
# git clone <LINK_REPOSITÓRIO>
# Se o link do repositório é, por exemplo, https://github.com/VickyVent/EttoreSecAntiRansomware, deve-se fazer o seguinte:
git clone https://github.com/VickyVent/EttoreSecAntiRansomware
```

### Compilação
São duas aplicações para se compilar, o CommunicationPortClient e o FsMiniFilter, os dois projetos dentro do repositório baixado. E isso pode ser feito da seguinte maneira: abrir a solução de cada um dos softwares (os arquivos cujas extensões são .sln) com o Visual Studio e clicar na opção de compilação.

### Colocando o Windows em modo de teste
Essa etapa é fundamental e não pode falhar. Para que se coloque o Windows em modo de teste, é necessário abrir o prompt de comando em modo de administrador e executar os seguintes comandos:
```batch
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
```

### Instalando certificado do FsMiniFilter
Na pasta referente ao FsMiniFilter, entre no seguinte diretório: x64/Debug. Lá haverá um arquivo chamado "FsMiniFilter.cer", que é o certificado a ser instalado. Portanto, clique com o botão direito no certificado e clique em instalar, e prossiga conforme necessário, sem fazer diversas alterações.

### Instalando o mini filter
No mesmo diretório acima, clique com o botão direito no arquivo "FsMiniFilter.inf", e execute a opção "Instalar".

### Testando a instalação do mini filter
Para se fazer uma prova real da instalação do mini filter, abra um prompt de comando em modo de administrador e execute o seguinte comando:
```batch
sc query FsMiniFilter
```

Caso uma mensagem de erro apareça, o mini filter não foi instalado, e você seguiu algum passo errado. Caso contrário, aparecerá estatísticas do minifilter, e uma delas indicará que ele não está sendo executado, mas fora instalado com sucesso.

### Executando os softwares
Por fim, para executar a aplicação de fato, você possui duas opções, que levam no mesmo fim:
 - Executar o mini filter e depois executar o CommunicationPortClient.
 - Executar o CommunicationPortClient e, em dez segundos, iniciar o mini filter. O CommunicationPortClient fica por dez segundos tentando se comunicar com o mini filter, e caso nesse período a conexão entre as duas aplicações não seja feita, o CommunicationPortClient será terminado.

De qualquer forma, os seguintes procedimentos devem ser feitos para executar cada um dos softwares:
 - Entrar no prompt de comando como administrador e executar o seguinte comando: `sc start FsMiniFilter`.
 - Entrar no diretório referente à compilação do CommunicationPortClient (CommunicationPortClient/x64/Debug) e executar o arquivo CommunicationPortClient.exe **como administrador**.


