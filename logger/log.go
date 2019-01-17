package logger

import "github.com/TykTechnologies/logrus"

func GetLogger(modName string) *logrus.Entry {
	log := logrus.WithField("app", "tk8s").WithField("mod", modName)
	return log
}
