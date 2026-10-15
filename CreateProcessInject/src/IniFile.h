#pragma once

#include <Windows.h>
#include <string>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

class IniFile
{
public:
    bool LoadFromFile(const std::string& path)
    {
        m_sections.clear();
        std::ifstream in(path);
        if (!in.is_open())
            return false;

        std::string line;
        std::string section;
        while (std::getline(in, line))
        {
            Trim(line);
            if (line.empty() || line[0] == ';' || line[0] == '#')
                continue;

            if (line.front() == '[' && line.back() == ']')
            {
                section = line.substr(1, line.size() - 2);
                Trim(section);
                continue;
            }

            auto eq = line.find('=');
            if (eq == std::string::npos)
                continue;

            std::string key = line.substr(0, eq);
            std::string val = line.substr(eq + 1);
            Trim(key);
            Trim(val);
            if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
                val = val.substr(1, val.size() - 2);

            m_sections[section][key] = val;
        }
        return true;
    }

    std::string GetString(const std::string& section, const std::string& key,
                          const std::string& defVal = "") const
    {
        auto s = m_sections.find(section);
        if (s == m_sections.end())
            return defVal;
        auto k = s->second.find(key);
        if (k == s->second.end())
            return defVal;
        return k->second;
    }

    int GetInt(const std::string& section, const std::string& key, int defVal = 0) const
    {
        auto v = GetString(section, key);
        if (v.empty())
            return defVal;
        try { return std::stoi(v, nullptr, 0); } catch (...) { return defVal; }
    }

    bool GetBool(const std::string& section, const std::string& key, bool defVal = false) const
    {
        auto v = GetString(section, key);
        if (v.empty())
            return defVal;
        std::string low;
        low.reserve(v.size());
        for (char c : v) low.push_back((char)std::tolower((unsigned char)c));
        if (low == "1" || low == "true" || low == "yes" || low == "on")
            return true;
        if (low == "0" || low == "false" || low == "no" || low == "off")
            return false;
        return defVal;
    }

private:
    static void Trim(std::string& s)
    {
        auto notSpace = [](unsigned char c) { return !std::isspace(c); };
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
        s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
    }

    std::unordered_map<std::string,
                       std::unordered_map<std::string, std::string>> m_sections;
};
