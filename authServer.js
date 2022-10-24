require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')

app.use(express.json())

//DB 대신에 발급한 갱신토큰값을 저장하는  변수
let refreshTokens = []


//토큰 갱신 
app.post('/token', (req, res) => {
  //refreshToken 값을 가져온다.
  const refreshToken = req.body.token

  //refreshToken 값이 없다면 401 에러 (유효한 인증 자격 증명이 없을때 코드 401)
  if (refreshToken == null) return res.sendStatus(401)

  // Forbidden으로 서버가 허용하지 않는 코드 403 내보낸다.
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)

  //토큰 확인
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403)

    //유효한 갱신토큰이면 accessToken 새로이 발급처리한다.
    const accessToken = generateAccessToken({ name: user.name })
    res.json({ accessToken: accessToken })
  })
})


//로그아웃 기존의 토큰 삭제
app.delete('/logout', (req, res) => {
  refreshTokens = refreshTokens.filter(token => token !== req.body.token)
  res.sendStatus(204)
})


//로그인시 토큰 생성
app.post('/login', (req, res) => {
  // Authenticate User

  const username = req.body.username
  const user = { name: username }

  //전근 토큰을 발행
  const accessToken = generateAccessToken(user)
  //갱신토큰 발행 
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)

  //DB 대신에 refreshTokens 변수에 발급한 갱신 토큰값을 저장한다.
  refreshTokens.push(refreshToken)

  console.log("1.로그인 토큰 발급 유저 아이디: ", req.body);
  console.log("2.로그인 토큰 발급 accessToken: ", accessToken);
  console.log("3.로그인 토큰 발급 refreshToken: ", refreshToken);

  //json 으로 반환처리
  res.json({ accessToken: accessToken, refreshToken: refreshToken })
})

// 시크릿 토큰 키값(ACCESS_TOKEN_SECRET)을 통해 토큰을 발행한다.(만료기간은 60초)
function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '60s' })
}

app.listen(4000)