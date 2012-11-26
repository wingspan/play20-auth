package jp.t2v.lab.play20.auth

import play.api.mvc._
import play.api.libs.iteratee.{Input, Done}
import scala.Left
import scala.Right

trait Auth {
  self: Controller with AuthConfig =>

  def authorizedAction(authority: Authority)(f: User => Request[AnyContent] => Result): Action[(AnyContent, User)] =
    authorizedAction(BodyParsers.parse.anyContent, authority)(f)

  def authorizedAction[A](p: BodyParser[A], authority: Authority)(f: User => Request[A] => Result): Action[(A, User)] = {
    val parser = BodyParser {
      req => authorized(authority)(req) match {
        case Right(user)  => p.map((_, user))(req)
        case Left(result) => Done(Left(result), Input.Empty)
      }
    }
    Action(parser) { req => f(req.body._2)(req.map(_._1)) }
  }

  def optionalUserAction(f: Option[User] => Request[AnyContent] => Result): Action[AnyContent] =
    optionalUserAction(BodyParsers.parse.anyContent)(f)

  def optionalUserAction[A](p: BodyParser[A])(f: Option[User] => Request[A] => Result): Action[A] =
    Action(p)(req => f(restoreUser(req))(req))

  def authorized(authority: Authority)(implicit request: RequestHeader): Either[Result, User] = for {
    user <- restoreUser(request).toRight(authenticationFailed(request)).right
    _    <- Either.cond(authorize(user, authority), (), authorizationFailed(request)).right
  } yield user

  private def restoreUser(implicit request: RequestHeader): Option[User] = for {
    cookie <- request.cookies.get(cookieName)
    token  <- CookieUtil.verifyHmac(cookie)
    userId <- idContainer.get(token)
    user   <- resolveUser(userId)
  } yield {
    idContainer.prolongTimeout(token, sessionTimeoutInSeconds)
    user
  }




  def authorizedActionDispatch(dispatch: Seq[(Authority, User => Request[AnyContent] => Result)]) = {
    authorizedActionDispatch[AnyContent](BodyParsers.parse.anyContent, dispatch)
  }

  def authorizedActionDispatch[A](bodyParser: BodyParser[A], dispatch: Seq[(Authority, User => Request[A] => Result)]) = {
    Action(bodyParser) { req =>
      type F = User => Request[A] => Result

      // find the first controller that authenticates and invoke it
      lazy val authResults:Seq[Either[Result, (User, F)]] =
        dispatch.map { case (authority, f:F) =>
          authorized(authority)(req).fold(
            err => Left(err),
            user => Right((user, f))
          )
        }

      val mRoute = authResults.find(_.isRight)
      val routeOrAuthError : Either[Result, (User, F)] = if (mRoute.isDefined) mRoute.get
                                                         else authResults.last  // the last error was from the most general attempt

      val result : Result = routeOrAuthError.fold(identity, { _ match { case (user, f) => f(user)(req)} })
      result
    }
  }

}
