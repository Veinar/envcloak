# Contributing to EnvCloak

Welcome, and thank you for your interest in contributing to **EnvCloak**! 🎉

This project thrives on collaboration, and we welcome contributors of all skill levels. Whether you're a seasoned developer or someone looking to learn and grow, you're in the right place. 💡

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [How You Can Help](#how-you-can-help)
3. [Reporting Issues](#reporting-issues)
4. [Contributing Code](#contributing-code)
5. [Coding Guidelines](#coding-guidelines)
6. [Need Help?](#need-help)
7. [Thank You!](#thank-you)

---

## Getting Started

1. **Star and Fork the Repository**  
   Start by starring 🌟 and forking this repository [here](https://github.com/Veinar/envcloak). It's an easy way to support the project.

2. **Clone Your Fork**  
   ```
   git clone https://github.com/YOUR-USERNAME/envcloak.git
   cd envcloak
   ```

3. **Set Up Your Environment**  
   Create a Python virtual environment:
   ```
   pip install venv
   python -m venv --prompt=envcloak .
   ```

4. **Install Necessary Packages**  
   Download and install the required packages, including development dependencies:
   ```
   pip install -e .[dev]
   ```

5. **You Are Ready to Go!**  
   Dive into the code and explore the repository to identify areas where you'd like to contribute.

---

## How You Can Help

There are many ways to contribute, and every bit counts!  

- 🐞 **Report bugs**  
- 💡 **Suggest new features**  
- 📖 **Improve documentation**  
- 🧪 **Write or improve tests**  
- 👨‍💻 **Fix an existing issue**  
- 🌟 **Spread the word about EnvCloak**

Even if you're new to open source, you can still contribute! Feel free to ask for guidance—we're here to help you learn. 🙌

---

## Reporting Issues

1. Search the [issue tracker](https://github.com/Veinar/envcloak/issues) to ensure your issue hasn't already been reported.
2. If it's a new issue, [open one here](https://github.com/Veinar/envcloak/issues/new).
3. Clearly describe:
   - **What happened?**
   - **What did you expect to happen?**
   - **Steps to reproduce the issue**
   - **Your environment** (e.g., OS, Python version)

---

## Contributing Code

1. **Check Existing Issues**  
   Browse [open issues](https://github.com/Veinar/envcloak/issues) to find something you'd like to work on. Feel free to ask for clarification if needed.

2. **Work on a Feature or Fix**  
   If you have an idea for a feature or fix, please discuss it first by opening a new issue or commenting on an existing one.

3. **Branch Off**  
   Create a new branch for your work:
   ```
   git checkout -b feature/your-feature-name
   ```

4. **Commit Changes**  
   Write meaningful commit messages:
   ```
   git commit -m "Brief summary of the change"
   ```

5. **Write Tests**  
   Add tests for any new functionality.

6. **Push and Open a Pull Request**  
   ```
   git push origin feature/your-feature-name
   ```
   Then, [open a pull request](https://github.com/Veinar/envcloak/pull/new/develop) and describe your changes.

---

## Coding Guidelines

To ensure consistency and maintain quality, please follow these guidelines:

- **Code Formatting:**  
  Use [Black](https://github.com/psf/black) to format your code:  
  ```
  black envcloak/
  ```

- **Linting:**  
  Use [Pylint](https://pylint.pycqa.org/) to check for linting issues:  
  ```
  pylint envcloak/
  ```

- **Security Scanning:**  
  Use [Bandit](https://bandit.readthedocs.io/) to check for security vulnerabilities:  
  ```
  bandit -v -r envcloak/
  ```

- **Naming:**  
  Use clear and descriptive names for variables, functions, and files.

- **Testing:**  
  Ensure all tests pass. Add tests for new features or bug fixes. Run tests with [Pytest](https://docs.pytest.org/):  
  ```
  pytest tests/
  ```

- **Readability:**  
  Optimize for clarity. Write comments where necessary to explain complex logic.

---

## Need Help?

If you have questions or need guidance:

- Open a discussion in the [Discussions tab](https://github.com/Veinar/envcloak/discussions).
- Tag a maintainer or other contributors on an issue or PR for help.
- Reach out via email or social media if listed in the repository.

---

## Thank You!

Your contributions make EnvCloak better for everyone. We're grateful for your support and excited to work with you! 💖

Let’s learn, grow, and build something amazing together.

---
