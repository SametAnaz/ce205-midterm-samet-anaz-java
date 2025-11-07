@echo off
@setlocal enableextensions
@cd /d "%~dp0"

cd password-app

echo ========================================
echo Generating Coverage Reports for Website
echo ========================================
echo.

REM Check if JaCoCo report already exists
if not exist "target\site\jacoco\jacoco.xml" (
    echo Step 1/5: Running tests and generating JaCoCo coverage report...
    call mvn test
    if %ERRORLEVEL% NEQ 0 (
        echo Tests failed! Please fix test errors first.
        pause
        exit /b %ERRORLEVEL%
    )
) else (
    echo Step 1/5: JaCoCo report already exists, skipping tests...
)

echo Step 2/5: Creating necessary folders...
if not exist "target\site\coveragereport" mkdir "target\site\coveragereport"
if not exist "target\site\doxygen\html" mkdir "target\site\doxygen\html"
if not exist "target\site\coverxygen" mkdir "target\site\coverxygen"

echo Step 3/5: Generating Doxygen documentation...
cd ..
doxygen Doxyfile >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Doxygen documentation generated successfully!
) else (
    echo Warning: Doxygen generation failed or not installed!
    echo Creating empty index.html as placeholder...
    echo ^<html^>^<body^>^<h1^>Doxygen not available^</h1^>^</body^>^</html^> > password-app\target\site\doxygen\html\index.html
)
cd password-app

echo Step 4/5: Generating HTML coverage report with ReportGenerator...
if exist "target\site\jacoco\jacoco.xml" (
    echo Running ReportGenerator...
    "%USERPROFILE%\.dotnet\tools\reportgenerator.exe" "-reports:target/site/jacoco/jacoco.xml" "-sourcedirs:src/main/java" "-targetdir:target/site/coveragereport" -reporttypes:Html
    if %ERRORLEVEL% EQU 0 (
        echo Coverage report generated successfully!
    ) else (
        echo Warning: ReportGenerator failed!
        echo Creating empty index.html as placeholder...
        echo ^<html^>^<body^>^<h1^>ReportGenerator failed^</h1^>^</body^>^</html^> > target\site\coveragereport\index.html
    )
) else (
    echo Warning: JaCoCo XML report not found!
    echo Creating empty index.html as placeholder...
    echo ^<html^>^<body^>^<h1^>JaCoCo report not found^</h1^>^</body^>^</html^> > target\site\coveragereport\index.html
)

echo Step 5/6: Generating documentation coverage with Coverxygen...
if exist "target\site\doxygen\xml" (
    echo Running Coverxygen...
    cd ..
    python -m coverxygen --xml-dir "%cd%\password-app\target\site\doxygen\xml" --src-dir "%cd%" --format lcov --output "%cd%\password-app\target\site\coverxygen\lcov.info" --prefix "%cd%\password-app\" 2>nul
    cd password-app
    if exist "target\site\coverxygen\lcov.info" (
        echo Coverxygen report generated successfully!
        echo ^<html^>^<head^>^<title^>Documentation Coverage^</title^>^</head^>^<body^>^<h1^>Documentation Coverage Report^</h1^>^<p^>Coverage data generated. ^<a href="lcov.info"^>Download lcov.info^</a^>^</p^>^<pre^> > target\site\coverxygen\index.html
        type target\site\coverxygen\lcov.info >> target\site\coverxygen\index.html
        echo ^</pre^>^</body^>^</html^> >> target\site\coverxygen\index.html
    ) else (
        echo Warning: Coverxygen failed to generate lcov.info!
        echo ^<html^>^<body^>^<h1^>Coverxygen failed^</h1^>^</body^>^</html^> > target\site\coverxygen\index.html
    )
) else (
    echo Warning: Doxygen XML output not found! Skipping Coverxygen...
    echo ^<html^>^<body^>^<h1^>Doxygen XML not available^</h1^>^</body^>^</html^> > target\site\coverxygen\index.html
)

echo Step 6/6: Generating Maven site...
call mvn site

echo.
echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo Starting web server at http://localhost:9000/
echo To Exit: Use CTRL+C
echo.
start http://localhost:9000/
mvn site:run

pause