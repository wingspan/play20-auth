Play2.0 module for Authentication and Authorization
===========================================================

これは Play2.0 のアプリケーションに認証/認可の機能を手軽に組み込むためのモジュールです。

動機
---------------------------------------

### 安全性
 
標準で提供されている `Security` トレイトでは、ユーザを識別する識別子を規定していません。

サンプルアプリケーションのように、E-mailアドレスやユーザIDなどを識別子として利用した場合、
万が一Cookieが流出した場合に、即座にSessionを無効にすることができません。

このモジュールでは、暗号論的擬似乱数を使用したSessionIDを生成し、
万が一Cookieが流失した場合でも、再ログインによるSessionIDの無効化や、タイムアウトを行うことができます。

### 拡張性

標準で提供されている `Security` トレイトでは、認証後に `Action` を返します。

これでは認証/認可以外にも様々なAction合成を行いたい場合にネストが深くなって非常に記述性が低くなります。

このモジュールでは `Either[PlainResult, User]` を返すインターフェイスを用意することで、
柔軟に他の操作を組み合わせて使用することができます。


導入
---------------------------------------

__※注意！リポジトリただいま準備中！！！！！！！__

`Build.scala` の `appDependencies` 及び `PlayProject.settings` 内に以下のような記述を追加します。

```scala
  val appDependencies = Seq(
    "jp.t2v" %% "play20.auth" % "0.1"
  )

  val main = PlayProject(appName, appVersion, appDependencies, mainLang = SCALA).settings(
    resolvers += "t2v.jp repo" at "http://t2v.github.com/maven-repo/release"
  )
```

使い方
---------------------------------------

1. `app/controllers` 以下に `jp.t2v.lab.play20.auth.AuthConfig` を実装した `trait` を作成します。

    ```scala
    // (例)
    trait AuthConfigImpl extends AuthConfig {
    
      /** 
       * ユーザを識別するIDの型です。String や Int や Long などが使われるでしょう。 
       */
      type Id = String
    
      /** 
       * あなたのアプリケーションで認証するユーザを表す型です。
       * User型やAccount型など、アプリケーションに応じて設定してください。 
       */
      type User = Account
    
      /** 
       * 認可(権限チェック)を行う際に、アクション毎に設定するオブジェクトの型です。
       * このサンプルでは例として以下のような trait を使用しています。
       *
       * sealed trait Permission
       * case object Administrator extends Permission
       * case object NormalUser extends Permission
       */
      type Authority = Permission
    
      /**
       * CacheからユーザIDを取り出すための ClassManifest です。
       * 基本的にはこの例と同じ記述をして下さい。
       */
      val idManifest: ClassManifest[Id] = classManifest[Id]
    
      /**
       * セッションタイムアウトの時間(秒)です。
       */
      val sessionTimeoutInSeconds: Int = 3600
    
      /**
       * ユーザIDからUserブジェクトを取得するアルゴリズムを指定します。
       * 任意の処理を記述してください。
       */
      def resolveUser(id: Id): Option[User] = Account.findById(id)
    
      /**
       * ログインが成功した際に遷移する先を指定します。
       */
      def loginSucceeded(request: Request[Any]): PlainResult = Redirect(routes.Message.main)
    
      /**
       * ログアウトが成功した際に遷移する先を指定します。
       */
      def logoutSucceeded(request: Request[Any]): PlainResult = Redirect(routes.Application.login)
    
      /**
       * 認証が失敗した場合に遷移する先を指定します。
       */
      def authenticationFailed(request: Request[Any]): PlainResult = Redirect(routes.Application.login)
    
      /**
       * 認可(権限チェック)が失敗した場合に遷移する先を指定します。
       */
      def authorizationFailed(request: Request[Any]): PlainResult = Forbidden("no permission")
    
      /**
       * 権限チェックのアルゴリズムを指定します。
       * 任意の処理を記述してください。
       */
      def authorize(user: User, authority: Authority): Boolean = 
        (user.permission, authority) match {
          case (Administrator, _) => true
          case (NormalUser, NormalUser) => true
          case _ => false
        }
    
    }
    ```

1. 次にログイン、ログアウトを行う `Controller` を作成します。
   この `Controller` に、先ほど作成した `AuthConfigImpl` トレイトと、
   `jp.t2v.lab.play20.auth.LoginLogout` トレイトを mixin します。

    ```scala
    object Application extends Controller with LoginLogout with AuthConfigImpl {
    
      /** ログインFormはアプリケーションに応じて自由に作成してください。 */
      val loginForm = Form {
        mapping("email" -> email, "password" -> text)(Account.authenticate)(_.map(u => (u.email, "")))
          .verifying("Invalid email or password", result => result.isDefined)
      }
    
      /** ログインページはアプリケーションに応じて自由に作成してください。 */
      def login = Action { implicit request =>
        Ok(html.login(loginForm))
      }
    
      /** 
       * ログアウト処理では任意の処理を行った後、
       * gotoLogoutSucceeded メソッドを呼び出した結果を返して下さい。
       * gotoLogoutSucceeded メソッドは PlainResult を返しますので、
       * 以下のように任意の処理を追加することもできます。
       * 
       *   gotoLogoutSucceeded.flashing(
       *     "success" -> "You've been logged out"
       *   )
       */
      def logout = Action { implicit request =>
        // do something...
        gotoLogoutSucceeded
      }
    
      /**
       * ログイン処理では認証が成功した場合、
       * gotoLoginSucceeded メソッドを呼び出した結果を返して下さい。
       * gotoLoginSucceeded メソッドも gotoLogoutSucceeded と同じく PlainResult を返しますので、
       * 任意の処理を追加することも可能です。
       */
      def authenticate = Action { implicit request =>
        loginForm.bindFromRequest.fold(
          formWithErrors => BadRequest(html.login(formWithErrors)),
          user => gotoLoginSucceeded(user.get.id)
        )
      }
    
    }
    ```

1. 最後は、好きな `Controller` に 先ほど作成した `AuthConfigImpl` トレイトと
   `jp.t2v.lab.play20.auth.Auth` トレイト を mixin すれば、認証/認可の仕組みを導入することができます。

    ```scala
    object Message extends Controller with Auth with AuthConfigImpl {
    
      // authorizedAction は 第一引数に権限チェック用の Authority を取り、
      // 第二引数に User => Request[Any] => Result な関数を取り、
      // Action を返します。
    
      def main = authorizedAction(NormalUser) { user => implicit request =>
        val title = "message main"
        Ok(html.message.main(title))
      }
    
      def list = authorizedAction(NormalUser) { user => implicit request =>
        val title = "all messages"
        Ok(html.message.list(title))
      }
    
      def detail(id: Int) = authorizedAction(NormalUser) { user => implicit request =>
        val title = "messages detail "
        Ok(html.message.detail(title + id))
      }
    
      // このActionだけ、Administrator でなければ実行できなくなります。
      def write = authorizedAction(Administrator) { user => implicit request =>
        val title = "write message"
        Ok(html.message.write(title))
      }
    
    }
    ```


高度な使い方
---------------------------------------

### 他のAction操作と合成する

後で書く


### リクエストパラメータに応じて権限判定を変更する

例えば SNS のようなアプリケーションでは、メッセージの編集といった機能があります。

しかしこのメッセージ編集は、自分の書いたメッセージは編集可能だけども、
他のユーザが書いたメッセージは編集禁止にしなくてはいけません。

そういった場合にも以下のように `Authority` を関数にすることで簡単に対応が可能です。

```scala
trait AuthConfigImpl extends AuthConfig {

  // 他の設定省略

  type Authority = User => Boolean

  def authorize(user: User, authority: Authority): Boolean = authority(user)

}
```

```scala
object Application extends Controller with Auth with AuthConfig {

  def checkAuthor(messageId: Int)(account: Account): Boolean =
    Message.getAuther(messageId) == account

  def edit(messageId: Int) = authorizedAction(checkAuthor(messageId)) { user => request =>
    val target = Message.findById(messageId)
    Ok(html.message.edit(messageForm.fill(target)))
  }

}
```


### ログイン後、認証直前にアクセスしていたページに遷移する

アプリケーションの任意のページにアクセスしてきた際に、
未ログイン状態であればログインページに遷移し、
ログインが成功した後に最初にアクセスしてきたページに戻したい、といった要求があります。

その場合も以下のようにするだけで簡単に実現できます。

```scala
trait AuthConfigImpl extends AuthConfig {

  // 他の設定省略

  def authenticationFailed(request: Request[Any]): PlainResult = 
    Redirect(routes.Application.login).withSession("access_uri" -> request.uri)

  def loginSucceeded(request: Request[Any]): PlainResult = {
    val uri = request.session.get("access_uri").getOrElse(routes.Message.main.url)
    request.session - "access_uri"
    Redirect(uri)
  }

}
```


ライセンス
---------------------------------------

このモジュールは Apache Software License, version 2 の元に公開します。

詳しくは `LICENSE` ファイルを参照ください。
